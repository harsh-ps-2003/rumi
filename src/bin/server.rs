use crate::rumi_proto::{
    discovery_server::{Discovery, DiscoveryServer},
    FindRequest, FindResponse, GetPublicSetRequest, GetPublicSetResponse, RegisterRequest,
    RegisterResponse, BucketEntry, GetMerkleProofRequest, GetMerkleProofResponse,
};
use console::style;
use lazy_static::lazy_static;
use p256::EncodedPoint;
use prometheus::{
    core::Collector, register_gauge_vec, register_histogram_vec, register_int_counter_vec, Encoder,
    GaugeVec, HistogramVec, IntCounterVec, Registry, TextEncoder,
};
use reqwest;
use rumi::Server;
use serde_json;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
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

// Metrics handler function
fn get_metrics() -> String {
    let encoder = TextEncoder::new();
    let mut buffer = Vec::new();
    encoder.encode(&REGISTRY.gather(), &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}

#[derive(Debug)]
pub struct DiscoveryService {
    server: Arc<Mutex<Server>>,
}

impl DiscoveryService {
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        let users = HashMap::new(); // Start with empty user set
        let server = Server::new(&mut rng, &users);
        debug!("Server initialized with empty user set");
        Self {
            server: Arc::new(Mutex::new(server)),
        }
    }
}

#[tonic::async_trait]
impl Discovery for DiscoveryService {
    #[instrument(skip(self, request), name = "register", ret)]
    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        let timer = REQUEST_DURATION
            .with_label_values(&["register"])
            .start_timer();
        REQUEST_COUNTER.with_label_values(&["register"]).inc();

        let result = {
            let request_inner = request.into_inner();
            let identifier = request_inner.identifier;
            let uuid_bytes = request_inner.uuid;
            let commitment = request_inner.commitment;

            let uuid = Uuid::from_slice(&uuid_bytes)
                .map_err(|_| Status::invalid_argument("Invalid UUID format"))?;

            let mut rng = rand::thread_rng();
            let mut server = self
                .server
                .lock()
                .map_err(|_| Status::internal("Server lock poisoned"))?;

            match server.register(identifier, commitment, &uuid, &mut rng) {
                Ok(merkle_proof) => {
                    debug!("Generated Merkle proof of length {}", merkle_proof.len());
                    Ok(Response::new(RegisterResponse {
                        success: true,
                        message: "Successfully registered identifier".to_string(),
                        merkle_proof,
                    }))
                },
                Err(e) => Ok(Response::new(RegisterResponse {
                    success: false,
                    message: e.to_string(),
                    merkle_proof: Vec::new(),
                })),
            }
        };

        timer.observe_duration();
        result
    }

    #[instrument(skip(self, request), name = "find", ret)]
    async fn find(&self, request: Request<FindRequest>) -> Result<Response<FindResponse>, Status> {
        let timer = REQUEST_DURATION.with_label_values(&["find"]).start_timer();
        REQUEST_COUNTER.with_label_values(&["find"]).inc();

        let result = {
            let request_inner = request.into_inner();
            let prefix = request_inner
                .hash_prefix
                .try_into()
                .map_err(|_| Status::invalid_argument("Invalid prefix length"))?;
            let proof_data = (
                request_inner.zk_proof,
                request_inner.zk_verification_key,
            );

            let mut rng = rand::thread_rng();
            let server = self
                .server
                .lock()
                .map_err(|_| Status::internal("Server lock poisoned"))?;

            match server.find_bucket(prefix, &proof_data, &mut rng) {
                Some(bucket) => {
                    let entries = bucket
                        .into_iter()
                        .map(|(k, v)| BucketEntry {
                            double_blinded_identifier: k,
                            blinded_user_id: v,
                        })
                        .collect();

                    Ok(Response::new(FindResponse { entries }))
                }
                None => Err(Status::permission_denied("Invalid ZK proof")),
            }
        };

        timer.observe_duration();
        result
    }

    #[instrument(skip(self, _request), name = "get_public_set", ret)]
    async fn get_public_set(
        &self,
        _request: Request<GetPublicSetRequest>,
    ) -> Result<Response<GetPublicSetResponse>, Status> {
        let timer = REQUEST_DURATION
            .with_label_values(&["get_public_set"])
            .start_timer();
        REQUEST_COUNTER.with_label_values(&["get_public_set"]).inc();

        let result = {
            let server = self
                .server
                .lock()
                .map_err(|_| Status::internal("Server lock poisoned"))?;
            let merkle_root = server.get_merkle_root();
            Ok(Response::new(GetPublicSetResponse {
                merkle_root: merkle_root.to_vec(),
            }))
        };

        timer.observe_duration();
        result
    }

    #[instrument(skip(self, request), name = "get_merkle_proof", ret)]
    async fn get_merkle_proof(
        &self,
        request: Request<GetMerkleProofRequest>,
    ) -> Result<Response<GetMerkleProofResponse>, Status> {
        let timer = REQUEST_DURATION
            .with_label_values(&["get_merkle_proof"])
            .start_timer();
        REQUEST_COUNTER.with_label_values(&["get_merkle_proof"]).inc();

        let result = {
            let commitment = request.into_inner().commitment;
            let server = self.server.lock()
                .map_err(|_| Status::internal("Server lock poisoned"))?;
            
            // Generate proof from server's Merkle state
            match server.generate_merkle_proof(&commitment) {
                Ok(proof) => Ok(Response::new(GetMerkleProofResponse {
                    success: true,
                    message: "Successfully generated Merkle proof".to_string(),
                    merkle_proof: proof,
                })),
                Err(e) => Ok(Response::new(GetMerkleProofResponse {
                    success: false,
                    message: e,
                    merkle_proof: vec![],
                })),
            }
        };

        timer.observe_duration();
        result
    }
}

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
            match client
                .post("http://localhost:9091/metrics/job/rumi")
                .header("Content-Type", "text/plain")
                .body(metrics)
                .send()
                .await
            {
                Ok(response) => {
                    if !response.status().is_success() {
                        warn!(
                            "Failed to push metrics: HTTP {} - Body: {}",
                            response.status(),
                            response.text().await.unwrap_or_default()
                        );
                    } else {
                        debug!("Successfully pushed metrics");
                    }
                }
                Err(e) => {
                    warn!("Failed to push metrics: {}", e);
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(15)).await;
        }
    });

    TonicServer::builder()
        .add_service(DiscoveryServer::new(service))
        .serve(addr)
        .await?;

    Ok(())
}
