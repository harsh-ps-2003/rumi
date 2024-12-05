use clap::Parser;
use rumi::Client;
use rumi_proto::discovery_client::DiscoveryClient;
use rumi_proto::{FindRequest, FindResponse};
use std::error::Error;
use std::collections::HashMap;
use tonic::Response;

pub mod rumi_proto {
    tonic::include_proto!("rumi");
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    Lookup {
        #[arg(help = "The identifier to look up")]
        identifier: u64,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Lookup { identifier } => {
            let mut client = DiscoveryClient::connect("http://[::1]:50051").await?;
            let rumi_client = Client::new(rand::thread_rng());

            // Get public set from server first (in real implementation this would be cached)
            let public_set: Vec<u64> = (1_000_000_000..1_000_000_100).collect();

            // Generate blinded request
            let (prefix, blinded_point, zksm_proof) = rumi_client.request_identifier(identifier, &public_set);

            // Create and send request
            let request = tonic::Request::new(FindRequest {
                hash_prefix: prefix.to_vec(),
                blinded_identifier: blinded_point.as_bytes().to_vec(),
                zksm_proof: serde_json::to_string(&zksm_proof)?,
            });

            match client.find(request).await {
                Ok(response) => {
                    // Map the response to get the entries
                    let entries = response.get_ref().entries.clone();
                    let bucket: HashMap<_, _> = entries
                        .into_iter()
                        .map(|entry| {
                            (
                                p256::EncodedPoint::from_bytes(&entry.blinded_identifier).unwrap(),
                                p256::EncodedPoint::from_bytes(&entry.blinded_user_id).unwrap(),
                            )
                        })
                        .collect();

                    // Process response
                    if let Some(user_id_point) = rumi_client.find_user_id(&blinded_point, &bucket, identifier) {
                        println!("✅ Found matching UUID for identifier {}", identifier);
                        println!("UUID Point: {}", hex::encode(user_id_point.as_bytes()));
                    } else {
                        println!("❌ No match found for identifier {}", identifier);
                    }
                }
                Err(status) => {
                    println!("❌ Error: {}", status);
                }
            }
        }
    }

    Ok(())
}