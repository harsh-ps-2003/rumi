pub mod rumi_proto {
    tonic::include_proto!("rumi");
}

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

/// Lookup an identifier in the system
#[instrument(skip(client, rumi_client), fields(identifier = %identifier), ret)]
async fn lookup_identifier(
    client: &mut DiscoveryClient<tonic::transport::Channel>,
    rumi_client: &Client,
    identifier: u64,
) -> Result<(), Box<dyn Error>> {
    let public_set = client
        .get_public_set(GetPublicSetRequest {})
        .await?
        .into_inner()
        .identifiers;

    if !public_set.contains(&identifier) {
        info!(
            "{} Identifier {} not found in the system",
            style("✗").red().bold(),
            style(identifier).cyan()
        );
        return Ok(());
    }

    info!("Looking up identifier {}", style(identifier).cyan());

    // Generate blinded request
    let (prefix, blinded_point, zksm_proof) =
        rumi_client.request_identifier(identifier, &public_set);

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
            let double_blinded_point =
                p256::EncodedPoint::from_bytes(&response.double_blinded_identifier)
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

            if let Some(user_id_point) =
                rumi_client.find_user_id(&double_blinded_point, &bucket, identifier)
            {
                info!(
                    "{} Found matching UUID for identifier {}",
                    style("✓").green().bold(),
                    style(identifier).cyan()
                );
                info!(
                    "UUID: {}",
                    style(hex::encode(&user_id_point.as_bytes()[1..17])).yellow()
                );
            } else {
                info!(
                    "{} No matching record found for identifier {}",
                    style("✗").red().bold(),
                    style(identifier).cyan()
                );
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

/// Register an identifier in the system
#[instrument(skip(client), fields(identifier = %identifier), ret)]
async fn register_identifier(
    client: &mut DiscoveryClient<tonic::transport::Channel>,
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

    let request = tonic::Request::new(RegisterRequest {
        identifier,
        uuid: uuid.as_bytes().to_vec(),
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

/// Main function to start the client
#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
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
            register_identifier(&mut client, identifier, uuid).await?;
        }
    }

    Ok(())
}
