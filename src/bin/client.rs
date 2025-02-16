use clap::Parser;
use console::style;
use rumi::Client;
use rumi_proto::{
    discovery_client::DiscoveryClient, FindRequest, FindResponse, GetPublicSetRequest,
    GetPublicSetResponse, RegisterRequest, RegisterResponse,
};
use std::collections::HashMap;
use std::error::Error;
use std::vec;
use tonic::Response;
use tracing::{debug, info, trace, warn, Level};
use tracing_attributes::instrument;
use tracing_subscriber::{fmt, prelude::*};
use uuid::Uuid;

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
    Register {
        #[arg(help = "The identifier to register")]
        identifier: u64,
        #[arg(help = "The UUID to register (optional, will generate if not provided)")]
        uuid: Option<String>,
    },
}

#[instrument(skip(client, rumi_client), fields(identifier = %identifier), ret)]
async fn lookup_identifier(
    client: &mut DiscoveryClient<tonic::transport::Channel>,
    rumi_client: &Client,
    identifier: u64,
) -> Result<(), Box<dyn Error>> {
    // Get the current Merkle root from the server
    let merkle_root = client
        .get_public_set(GetPublicSetRequest {})
        .await?
        .into_inner()
        .merkle_root;

    info!("Looking up identifier {}", style(identifier).cyan());

    // Convert identifier to string once
    let identifier_str = identifier.to_string();
    
    // Prepare the lookup request
    let (prefix, proof_data) = match rumi_client.prepare_lookup(&identifier_str).await {
        Ok(data) => data,
        Err(e) => {
            info!(
                "{} {}",
                style("✗").red().bold(),
                style(e).red()
            );
            return Ok(());
        }
    };
    
    debug!("Using prefix {:?} for lookup", prefix);
    let (zk_proof, zk_verification_key) = proof_data;
    debug!("Generated ZK proof of length {}", zk_proof.len());

    // Create and send request
    let request = tonic::Request::new(FindRequest {
        hash_prefix: prefix.to_vec(),
        zk_proof,
        zk_verification_key,
    });

    match client.find(request).await {
        Ok(response) => {
            let response = response.into_inner();
            let entries = response.entries;

            if entries.is_empty() {
                info!(
                    "{} No matching record found for identifier {}",
                    style("✗").red().bold(),
                    style(identifier).cyan()
                );
                return Ok(());
            }

            // Convert BucketEntry to the format expected by unblind_user_id
            let converted_entries: Vec<(Vec<u8>, Vec<u8>)> = entries
                .into_iter()
                .map(|entry| (entry.double_blinded_identifier, entry.blinded_user_id))
                .collect();

            // Try to find and unblind the matching UUID
            let found_uuid = rumi_client.unblind_user_id(&converted_entries);

            match found_uuid {
                Some(uuid) => {
                    info!(
                        "{} Found matching UUID for identifier {}",
                        style("✓").green().bold(),
                        style(identifier).cyan()
                    );
                    info!("UUID: {}", style(uuid).yellow());
                }
                None => {
                    info!(
                        "{} No matching record found for identifier {}",
                        style("✗").red().bold(),
                        style(identifier).cyan()
                    );
                }
            }
        }
        Err(status) => {
            warn!(
                "{} Lookup failed: {}",
                style("✗").red().bold(),
                style(status).red()
            );
        }
    }

    Ok(())
}

#[instrument(skip(client, rumi_client), fields(identifier = %identifier), ret)]
async fn register_identifier(
    client: &mut DiscoveryClient<tonic::transport::Channel>,
    rumi_client: &mut Client,
    identifier: u64,
    uuid_str: Option<String>,
) -> Result<(), Box<dyn Error>> {
    let uuid = if let Some(uuid_str) = uuid_str {
        Uuid::parse_str(&uuid_str)?
    } else {
        Uuid::new_v4()
    };

    info!(
        "Registering identifier {} with UUID {}",
        style(identifier).cyan(),
        style(uuid).yellow()
    );

    let (id, commitment) = rumi_client.prepare_registration(&identifier.to_string());

    let request = tonic::Request::new(RegisterRequest {
        identifier: id,
        uuid: uuid.as_bytes().to_vec(),
        commitment,
    });

    match client.register(request).await {
        Ok(response) => {
            let response = response.into_inner();
            if response.success {
                info!(
                    "{} {}",
                    style("✓").green().bold(),
                    style(&response.message).green()
                );
                debug!("Received Merkle proof of length {}", response.merkle_proof.len());
                if response.merkle_proof.is_empty() {
                    warn!("Received empty Merkle proof from server");
                } else {
                    rumi_client.store_merkle_proof(identifier.to_string(), response.merkle_proof);
                    debug!("Stored Merkle proof for identifier {}", identifier);
                }
            } else {
                info!(
                    "{} {}",
                    style("✗").red().bold(),
                    style(&response.message).red()
                );
            }
        }
        Err(status) => {
            warn!(
                "{} Registration failed: {}",
                style("✗").red().bold(),
                style(status).red()
            );
        }
    }

    Ok(())
}

#[tokio::main]
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

    let cli = Cli::parse();

    match cli.command {
        Commands::Lookup { identifier } => {
            let mut client = DiscoveryClient::connect("http://[::1]:50051").await?;
            let rumi_client = Client::new(rand::thread_rng());
            lookup_identifier(&mut client, &rumi_client, identifier).await?;
        }
        Commands::Register { identifier, uuid } => {
            let mut client = DiscoveryClient::connect("http://[::1]:50051").await?;
            let mut rumi_client = Client::new(rand::thread_rng());
            register_identifier(&mut client, &mut rumi_client, identifier, uuid).await?;
        }
    }

    Ok(())
}
