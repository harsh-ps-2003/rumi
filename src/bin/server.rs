use crate::rumi_proto::{GetPublicSetRequest, GetPublicSetResponse};
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
use tracing_subscriber::{fmt, prelude::*};
use uuid::Uuid;

pub mod rumi_proto {
    tonic::include_proto!("rumi");
}

use rumi_proto::{
    discovery_server::{Discovery, DiscoveryServer},
    FindRequest, FindResponse,
};

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
        let mut users = HashMap::new();

        for i in 0..100 {
            users.insert(1_000_000_000 + i, Uuid::new_v4());
        }

        let server = Server::new(&mut rng, &users);
        debug!(
            "Server initialized with identifiers: {:?}",
            server.get_public_set()
        );

        Self {
            server: Arc::new(Mutex::new(server)),
        }
    }
}

#[tonic::async_trait]
impl Discovery for DiscoveryService {
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
            let identifiers = server.get_public_set();
            Ok(Response::new(GetPublicSetResponse { identifiers }))
        };

        timer.observe_duration();
        result
    }

    async fn find(&self, request: Request<FindRequest>) -> Result<Response<FindResponse>, Status> {
        let timer = REQUEST_DURATION.with_label_values(&["find"]).start_timer();
        REQUEST_COUNTER.with_label_values(&["find"]).inc();

        let result = {
            let request_inner = request.into_inner();
            let hash_prefix = request_inner.hash_prefix;
            let client_blinded_identifier = request_inner.blinded_identifier;
            let zksm_proof = request_inner.zksm_proof;

            let prefix: [u8; 8] = hash_prefix
                .try_into()
                .map_err(|_| Status::invalid_argument("Invalid prefix length"))?;

            let mut rng = rand::thread_rng();

            // Get mutable lock once and keep it for the duration
            let mut server = self
                .server
                .lock()
                .map_err(|_| Status::internal("Server lock poisoned"))?;

            let client_blinded_point =
                p256::EncodedPoint::from_bytes(&client_blinded_identifier)
                    .map_err(|_| Status::invalid_argument("Invalid blinded identifier"))?;

            let double_blinded_point = server.blind_identifier(&client_blinded_point);

            match server.find_bucket(
                prefix,
                &serde_json::from_str(&zksm_proof)
                    .map_err(|_| Status::invalid_argument("Invalid ZKSM proof"))?,
                &mut rng,
            ) {
                Some(bucket) => {
                    let entries = bucket
                        .into_iter()
                        .map(|(k, v)| rumi_proto::BucketEntry {
                            blinded_identifier: k.as_bytes().to_vec(),
                            blinded_user_id: v.as_bytes().to_vec(),
                        })
                        .collect();

                    Ok(Response::new(FindResponse {
                        double_blinded_identifier: double_blinded_point.as_bytes().to_vec(),
                        entries,
                    }))
                }
                None => Err(Status::permission_denied("Invalid ZKSM proof")),
            }
        };

        timer.observe_duration();
        result
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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
                .post("http://localhost:9091/metrics/job/rumi") // Simplified endpoint
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
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        }
    });

    // Set up console and tracing
    let console_layer = console_subscriber::ConsoleLayer::builder()
        .with_default_env()
        .spawn();

    tracing_subscriber::registry()
        .with(console_layer)
        .with(
            fmt::layer()
                .with_target(false)
                .with_thread_ids(true)
                .with_file(true)
                .with_line_number(true)
                .with_level(true),
        )
        .init();

    info!("{}", style("RUMI Discovery Server").green().bold());
    info!("Listening on {}", style(addr).cyan());
    info!(
        "Initialized with {} identifiers",
        style(service.server.lock().unwrap().get_public_set().len()).yellow()
    );
    info!("Tokio Console available on http://127.0.0.1:6669");
    info!("Metrics being pushed to Prometheus");

    debug!(
        "Public set: {:?}",
        service.server.lock().unwrap().get_public_set()
    );

    TonicServer::builder()
        .add_service(DiscoveryServer::new(service))
        .serve(addr)
        .await?;

    Ok(())
}
