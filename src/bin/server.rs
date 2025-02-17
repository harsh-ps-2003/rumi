use crate::rumi_proto::{
    discovery_server::{Discovery, DiscoveryServer},
    FindRequest, FindResponse, GetPublicSetRequest, GetPublicSetResponse, RegisterRequest,
    RegisterResponse,
};
use console::style;
use lazy_static::lazy_static;
use p256::EncodedPoint;
use prometheus::{
    core::Collector, register_gauge_vec, register_histogram_vec, register_int_counter_vec, Encoder,
    GaugeVec, HistogramVec, IntCounterVec, Registry, TextEncoder,
};
use reqwest;
use rumi::{Server, actor::ServerActor};
use serde_json;
use std::collections::HashMap;
use std::net::SocketAddr;
use tonic::{transport::Server as TonicServer, Request, Response, Status};
use tracing::{debug, info, warn, Level};
use tracing_attributes::instrument;
use tracing_subscriber::{fmt, prelude::*};
use uuid::Uuid;

pub mod rumi_proto {
    tonic::include_proto!("rumi");
}

// Define metrics
lazy_static! {
    static ref REGISTRY: Registry = Registry::new();
    static ref REQUEST_COUNTER: IntCounterVec = register_int_counter_vec!(
        "rumi_requests_total",
        "Total number of requests received",
        &["endpoint"]
    )
    .unwrap();
    static ref REQUEST_DURATION: HistogramVec = register_histogram_vec!(
        "rumi_request_duration_seconds",
        "Request duration in seconds",
        &["endpoint"],
        vec![0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
    )
    .unwrap();
    static ref MEMORY_GAUGE: GaugeVec =
        register_gauge_vec!("rumi_memory_bytes", "Memory usage in bytes", &["type"]).unwrap();
}

/// Metrics handler function
fn get_metrics() -> String {
    let encoder = TextEncoder::new();
    let mut buffer = Vec::new();
    encoder.encode(&REGISTRY.gather(), &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}

/// Discovery service implementation
/// Uses actor model for handling server state
#[derive(Debug, Clone)]
pub struct DiscoveryService {
    server_handle: rumi::actor::ServerHandle,
}

impl DiscoveryService {
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        let users = HashMap::new(); // Start with empty user set

        let server = Server::new(&mut rng, &users);
        debug!("Server initialized with empty user set");

        let server_handle = ServerActor::spawn(server);

        Self { server_handle }
    }
}

#[tonic::async_trait]
impl Discovery for DiscoveryService {
    /// Get the public set of identifiers
    #[instrument(skip(self, _request), name = "get_public_set", ret)]
    async fn get_public_set(
        &self,
        _request: Request<GetPublicSetRequest>,
    ) -> Result<Response<GetPublicSetResponse>, Status> {
        let timer = REQUEST_DURATION
            .with_label_values(&["get_public_set"])
            .start_timer();
        REQUEST_COUNTER.with_label_values(&["get_public_set"]).inc();

        let identifiers = self.server_handle.get_public_set().await;
        let result = Ok(Response::new(GetPublicSetResponse { identifiers }));

        timer.observe_duration();
        result
    }

    /// Find a user by their identifier
    #[instrument(
        skip(self, request),
        fields(
            prefix_len = %request.get_ref().hash_prefix.len(),
        ),
        ret
    )]
    async fn find(&self, request: Request<FindRequest>) -> Result<Response<FindResponse>, Status> {
        let timer = REQUEST_DURATION.with_label_values(&["find"]).start_timer();
        REQUEST_COUNTER.with_label_values(&["find"]).inc();

        let request_inner = request.into_inner();
        let hash_prefix = request_inner.hash_prefix;
        let client_blinded_identifier = request_inner.blinded_identifier;
        let zksm_proof = request_inner.zksm_proof;

        let prefix: [u8; 8] = hash_prefix
            .try_into()
            .map_err(|_| Status::invalid_argument("Invalid prefix length"))?;

        let result = match self.server_handle.find(prefix, client_blinded_identifier, zksm_proof).await {
            Some((double_blinded_identifier, entries)) => {
                let entries = entries
                    .into_iter()
                    .map(|(k, v)| rumi_proto::BucketEntry {
                        blinded_identifier: k,
                        blinded_user_id: v,
                    })
                    .collect();

                Ok(Response::new(FindResponse {
                    double_blinded_identifier,
                    entries,
                }))
            }
            None => Err(Status::permission_denied("Invalid ZKSM proof")),
        };

        timer.observe_duration();
        result
    }

    /// Register a new user
    #[instrument(skip(self, request), name = "register", ret)]
    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        let timer = REQUEST_DURATION
            .with_label_values(&["register"])
            .start_timer();
        REQUEST_COUNTER.with_label_values(&["register"]).inc();

        let request_inner = request.into_inner();
        let identifier = request_inner.identifier;
        let uuid_bytes = request_inner.uuid;

        let uuid = Uuid::from_slice(&uuid_bytes)
            .map_err(|_| Status::invalid_argument("Invalid UUID format"))?;

        let result = match self.server_handle.register(identifier, uuid).await {
            Ok(()) => Ok(Response::new(RegisterResponse {
                success: true,
                message: format!("Successfully registered identifier {}", identifier),
            })),
            Err(e) => Ok(Response::new(RegisterResponse {
                success: false,
                message: e.to_string(),
            })),
        };

        timer.observe_duration();
        result
    }
}

/// Main function to start the server
#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Set up logging based on RUST_LOG env var, defaulting to info level
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    tracing_subscriber::fmt()
        .with_target(false)
        .with_thread_ids(false)
        .with_line_number(false)
        .with_level(true)
        .with_env_filter(env_filter)
        .init();

    let addr = "[::1]:50051".parse()?;
    let service = DiscoveryService::new();

    // Register metrics
    REGISTRY
        .register(Box::new(REQUEST_COUNTER.clone()))
        .unwrap();
    REGISTRY
        .register(Box::new(REQUEST_DURATION.clone()))
        .unwrap();
    REGISTRY.register(Box::new(MEMORY_GAUGE.clone())).unwrap();

    info!("RUMI Server starting up on {}", style(addr).cyan());

    // Start metrics pushing in background
    tokio::spawn(async {
        let client = reqwest::Client::new();
        loop {
            // Generate some test metrics
            REQUEST_COUNTER.with_label_values(&["test"]).inc();
            MEMORY_GAUGE
                .with_label_values(&["heap"])
                .set(rand::random::<f64>() * 1000.0);

            let metrics = get_metrics();
            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
        }
    });

    TonicServer::builder()
        .add_service(DiscoveryServer::new(service))
        .serve(addr)
        .await?;

    Ok(())
}
