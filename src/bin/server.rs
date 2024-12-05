use rumi::Server;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tonic::{transport::Server as TonicServer, Request, Response, Status};
use uuid::Uuid;
use serde_json;
use p256::EncodedPoint;

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
        // Initialize with some demo data
        let mut rng = rand::thread_rng();
        let mut users = HashMap::new();
        
        // Add some demo phone numbers and UUIDs
        for i in 0..100 {
            users.insert(1_000_000_000 + i, Uuid::new_v4());
        }
        
        Self {
            server: Arc::new(Mutex::new(Server::new(&mut rng, &users))),
        }
    }
}

#[tonic::async_trait]
impl Discovery for DiscoveryService {
    async fn find(
        &self,
        request: Request<FindRequest>,
    ) -> Result<Response<FindResponse>, Status> {
        let request_inner = request.into_inner();

        let hash_prefix = request_inner.hash_prefix;
        let zksm_proof = request_inner.zksm_proof;
        
        // Convert protobuf types to native types
        let prefix: [u8; 8] = hash_prefix
            .try_into()
            .map_err(|_| Status::invalid_argument("Invalid prefix length"))?;
            
        let mut rng = rand::thread_rng();

        println!("Received ZKSM proof: {:?}", &zksm_proof);
        
        // Lock the server for the duration of find_bucket call
        let result = self.server
            .lock()
            .map_err(|_| Status::internal("Server lock poisoned"))?
            .find_bucket(
                prefix,
                &serde_json::from_str(&zksm_proof)
                    .map_err(|_| Status::invalid_argument("Invalid ZKSM proof"))?,
                &mut rng,
            );

        match result {
            Some(bucket) => {
                // Convert bucket to protobuf response with proper type handling
                let entries = bucket
                    .into_iter()
                    .map(|(k, v)| rumi_proto::BucketEntry {
                        blinded_identifier: k.as_bytes().to_vec(),
                        blinded_user_id: v.as_bytes().to_vec(),
                    })
                    .collect();

                Ok(Response::new(FindResponse { entries }))
            }
            None => {
                Err(Status::permission_denied("Invalid ZKSM proof {:?}"))
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse()?;
    let service = DiscoveryService::new();
    
    println!("RUMI Discovery Server listening on {}", addr);

    TonicServer::builder()
        .add_service(DiscoveryServer::new(service))
        .serve(addr)
        .await?;

    Ok(())
}