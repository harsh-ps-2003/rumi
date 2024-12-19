use crate::rumi_proto::{GetPublicSetRequest, GetPublicSetResponse};
use console::style;
use p256::EncodedPoint;
use rumi::Server;
use serde_json;
use std::collections::HashMap;
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
        let server = self
            .server
            .lock()
            .map_err(|_| Status::internal("Server lock poisoned"))?;
        let identifiers = server.get_public_set();
        Ok(Response::new(GetPublicSetResponse { identifiers }))
    }

    async fn find(&self, request: Request<FindRequest>) -> Result<Response<FindResponse>, Status> {
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

        let client_blinded_point = p256::EncodedPoint::from_bytes(&client_blinded_identifier)
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
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse()?;
    let service = DiscoveryService::new();

    // Set up single combined subscriber
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
