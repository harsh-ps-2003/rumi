use clap::Parser;
use rumi::Client;
use rumi_proto::discovery_client::DiscoveryClient;
use rumi_proto::{FindRequest, FindResponse, GetPublicSetRequest, GetPublicSetResponse};
use std::collections::HashMap;
use std::error::Error;
use std::vec;
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

async fn lookup_identifier(
    client: &mut DiscoveryClient<tonic::transport::Channel>,
    rumi_client: &Client,
    identifier: u64,
) -> Result<(), Box<dyn Error>> {
    // First get the public set from server
    let public_set = client
        .get_public_set(GetPublicSetRequest {})
        .await?
        .into_inner()
        .identifiers;

    println!("Retrieved public set: {:?}", public_set);
    
    if !public_set.contains(&identifier) {
        println!("❌ Identifier {} not in public set", identifier);
        return Ok(());
    }

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
            let response = response.into_inner();
            
            // Convert double_blinded_identifier to EncodedPoint
            let double_blinded_point = p256::EncodedPoint::from_bytes(&response.double_blinded_identifier)
                .map_err(|_| "Invalid double blinded identifier")?;

            // Convert response entries to HashMap
            let bucket: HashMap<_, _> = response
                .entries
                .into_iter()
                .map(|entry| {
                    (
                        p256::EncodedPoint::from_bytes(&entry.blinded_identifier).unwrap(),
                        p256::EncodedPoint::from_bytes(&entry.blinded_user_id).unwrap(),
                    )
                })
                .collect();

            if let Some(user_id_point) = rumi_client.find_user_id(&double_blinded_point, &bucket, identifier) {
                println!("✅ Found matching UUID for identifier {}", identifier);
                println!("UUID Point: {}", hex::encode(user_id_point.as_bytes()));
            } else {
                println!("❌ No match found for identifier {}", identifier);
                println!("Debug info:");
                println!("Bucket size: {}", bucket.len());
                println!("Double blinded point: {:?}", double_blinded_point);
                println!("Bucket contents: {:?}", bucket.keys().collect::<Vec<_>>());
            }
        }
        Err(status) => {
            println!("❌ Error: {}", status);
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Lookup { identifier } => {
            let mut client = DiscoveryClient::connect("http://[::1]:50051").await?;
            let rumi_client = Client::new(rand::thread_rng());
            lookup_identifier(&mut client, &rumi_client, identifier).await?;
        }
    }

    Ok(())
}
