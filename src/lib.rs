pub mod oram;
pub mod merkle;

// Include generated gRPC code
pub mod rumi {
    tonic::include_proto!("rumi");
}

use crate::{
    merkle::{MerkleState, generate_proof, verify_set_membership_proof},
    oram::{Operation, PathORAM, ORAM_DEPTH, get_prefix},
    rumi::{discovery_client::DiscoveryClient, GetMerkleProofRequest, GetMerkleRootRequest},
};
use rs_merkle::{
    Hasher, MerkleTree, MerkleProof,
    algorithms::Sha256 as MerkleHasher,
};
use p256::{
    elliptic_curve::{
        hash2curve::{ExpandMsgXmd, FromOkm, GroupDigest},
        ops::ReduceNonZero,
        sec1::{self, FromEncodedPoint, ToEncodedPoint},
        Field, Scalar,
    },
    AffinePoint,  // point satisfying the curve
    EncodedPoint, // compact representation of a point on curve for storing
    NistP256,
    ProjectivePoint, // alternative representation of a point on curve for simplifying calculations
    PublicKey,
    SecretKey,
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tracing::{debug, trace, warn};
use tracing_attributes::instrument;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};
use ark_bn254::Fr;
use hex;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::PathBuf;
use tokio::runtime::Runtime;
use tonic::transport::Channel;

/// A fixed-size prefix of an SHA-256 hash.
pub type Prefix = [u8; PREFIX_LEN];
// for truncation of hashed_identifier
const PREFIX_LEN: usize = 8;
const FIXED_ACCESSES: usize = 1000;

#[derive(Serialize, Deserialize)]
struct ORAMBlock {
    blinded_identifier: EncodedPoint,
    blinded_user_id: EncodedPoint,
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("storage_size", &self.storage.len())
            .field("merkle_root", &hex::encode(self.merkle_state.root()))
            .finish()
    }
}

pub struct Server {
    merkle_state: MerkleState,
    oram: PathORAM,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("commitments_count", &self.commitments.len())
            .finish()
    }
}

pub struct Client {
    client_secret: SecretKey,
    blinding_key: SecretKey,  // For double blinding
    commitments: HashMap<String, Vec<u8>>,
    storage_path: PathBuf,
}

impl Server {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R, users: &HashMap<String, Uuid>) -> Self {
        let mut merkle_state = MerkleState::new();
        let mut oram = PathORAM::new();

        // Initialize storage with existing users if any
        for (identifier, uuid) in users {
            // Create commitment for existing users
            let commitment = Self::create_commitment(identifier);
            
            // Add commitment to Merkle tree
            if let Ok(_) = merkle_state.add_leaf(&commitment) {
                // Only add to ORAM if Merkle tree addition succeeds
                let prefix = get_prefix(&commitment);
                let block = ORAMBlock {
                    blinded_identifier: commitment.clone(),  // Use commitment as blinded ID for existing users
                    blinded_user_id: uuid.as_bytes().to_vec(),
                };
                oram.access(Operation::Write, prefix, Some(block), rng);
            }
        }

        Self {
            merkle_state,
            oram,
        }
    }

    pub fn find_bucket(
        &self,
        prefix: [u8; 8],
        proof_data: &(Vec<u8>, Vec<u8>), // (proof_bytes, vk_bytes)
        rng: &mut impl RngCore,
    ) -> Option<Vec<(Vec<u8>, Vec<u8>)>> {
        // Extract commitment and verify Schnorr-like proof
        let verified = verify_set_membership_proof(
            &proof_data.0, // proof bytes
            &proof_data.1, // verification key bytes
            self.merkle_state.root(),
        ).ok()?;
            
        if !verified {
            return None;
        }
        
        // Read from ORAM
        let blocks = self.oram.access(Operation::Read, prefix, None, rng)?;
        
        // Convert ORAMBlocks to the expected format
        Some(blocks.into_iter()
            .map(|block| (block.blinded_identifier, block.blinded_user_id))
            .collect())
    }

    pub fn register(
        &mut self,
        blinded_id: Vec<u8>,
        commitment: Vec<u8>,
        uuid: &Uuid,
        rng: &mut impl RngCore,
    ) -> Result<Vec<u8>, String> {
        // Verify the commitment format
        if commitment.len() != 32 {
            return Err("Invalid commitment format".to_string());
        }
        
        // Get prefix from commitment
        let prefix = get_prefix(&commitment);
        
        // Create ORAM block
        let block = ORAMBlock {
            blinded_identifier: blinded_id,
            blinded_user_id: uuid.as_bytes().to_vec(),
        };
        
        // Store in ORAM
        self.oram.access(Operation::Write, prefix, Some(block), rng);

        // Add commitment to Merkle tree and get proof
        let merkle_proof = self.merkle_state.add_leaf(&commitment)
            .map_err(|e| format!("Failed to create Merkle proof: {}", e))?;
            
        debug!("Generated Merkle proof of length {}", merkle_proof.len());
        Ok(merkle_proof)
    }

    pub fn get_merkle_root(&self) -> [u8; 32] {
        self.merkle_state.root()
    }

    pub fn generate_merkle_proof(&self, commitment: &[u8]) -> Result<Vec<u8>, String> {
        self.merkle_state.generate_proof(commitment)
    }

    /// Create a commitment from an identifier
    fn create_commitment(identifier: &str) -> Vec<u8> {
        // Hash using SHA256
        let mut hasher = Sha256::new();
        hasher.update(identifier.as_bytes());
        let hash = hasher.finalize();
        
        // Second hash using MerkleHasher
        MerkleHasher::hash(&hash).to_vec()
    }
}

impl Client {
    pub fn new(mut rng: impl CryptoRng + RngCore) -> Self {
        // Create storage directory if it doesn't exist
        let storage_path = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".rumi");
        fs::create_dir_all(&storage_path).expect("Failed to create storage directory");

        // Load existing commitments if any
        let mut commitments = HashMap::new();
        let commitments_path = storage_path.join("commitments");
        if commitments_path.exists() {
            if let Ok(mut file) = File::open(&commitments_path) {
                let mut contents = String::new();
                if file.read_to_string(&mut contents).is_ok() {
                    for line in contents.lines() {
                        if let Some((id, commitment_hex)) = line.split_once(':') {
                            if let Ok(commitment) = hex::decode(commitment_hex) {
                                commitments.insert(id.to_string(), commitment);
                            }
                        }
                    }
                }
            }
        }

        Self {
            client_secret: SecretKey::random(&mut rng),
            blinding_key: SecretKey::random(&mut rng),
            commitments,
            storage_path,
        }
    }

    fn store_commitment(&mut self, identifier: String, commitment: Vec<u8>) {
        // Store in memory
        self.commitments.insert(identifier.clone(), commitment.clone());
        
        // Persist to file
        let commitments_path = self.storage_path.join("commitments");
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&commitments_path)
        {
            if let Err(e) = writeln!(file, "{}:{}", identifier, hex::encode(&commitment)) {
                warn!("Failed to persist commitment: {}", e);
            }
        }
    }

    /// Generate a blinded commitment from an identifier
    fn generate_commitment(&self, identifier: &str) -> Vec<u8> {
        // First blind the identifier
        let blinded_id = self.blind_identifier(identifier)
            .expect("Blinding should not fail");
        
        // Hash the blinded identifier using MerkleHasher
        MerkleHasher::hash(&blinded_id).to_vec()
    }

    pub fn prepare_registration(&mut self, identifier: &str) -> (Vec<u8>, Vec<u8>) {
        // Generate the blinded commitment
        let commitment = self.generate_commitment(identifier);
        
        // Store the commitment
        self.store_commitment(identifier.to_string(), commitment.clone());
        
        // Blind the identifier for server
        let blinded_id = self.blind_identifier(identifier)
            .expect("Blinding should not fail");
        
        (blinded_id, commitment)
    }

    pub async fn store_merkle_proof(&mut self, identifier: String, merkle_proof: Vec<u8>) -> Result<(), String> {
        // Store the Merkle proof for later use in ZKP generation
        let proof_path = self.storage_path.join(format!("{}.proof", identifier));
        tokio::fs::write(&proof_path, &merkle_proof)
            .await
            .map_err(|e| format!("Failed to store Merkle proof: {}", e))?;
        Ok(())
    }

    pub async fn prepare_lookup(&self, identifier: &str) -> Result<(Prefix, (Vec<u8>, Vec<u8>)), String> {
        // Retrieve the stored commitment
        let commitment = self.commitments.get(identifier)
            .ok_or_else(|| "No commitment found for identifier".to_string())?
            .clone();

        // Try to load stored Merkle proof
        let proof_path = self.storage_path.join(format!("{}.proof", identifier));
        let merkle_proof = if let Ok(proof) = tokio::fs::read(&proof_path).await {
            proof
        } else {
            // If no stored proof, get it from server
            let proof = get_merkle_proof_from_server(&commitment).await?;
            
            // Verify the proof against server's root
            let root = get_merkle_root_from_server().await?;
            if !verify_merkle_proof(&commitment, &proof, &root)? {
                return Err("Invalid Merkle proof from server".to_string());
            }
            
            // Store the verified proof
            self.store_merkle_proof(identifier.to_string(), proof.clone()).await?;
            proof
        };

        // Generate Schnorr-like proof using the commitment and Merkle proof
        let (zk_proof, vk) = generate_proof(&commitment, &merkle_proof)?;

        // Get prefix for the bucket lookup
        let prefix = get_prefix(&commitment);

        Ok((prefix, (zk_proof, vk)))
    }

    fn blind_identifier(&self, identifier: &str) -> Result<Vec<u8>, String> {
        // Hash the identifier to a curve point
        let point = hash_to_curve_point(identifier)?;
        
        // First blinding with client_secret
        let scalar1 = *self.client_secret.to_nonzero_scalar();
        let intermediate = point * scalar1;
        
        // Second blinding with blinding_key
        let scalar2 = *self.blinding_key.to_nonzero_scalar();
        let blinded = intermediate * scalar2;
        
        Ok(blinded.to_affine().to_encoded_point(false).as_bytes().to_vec())
    }

    pub fn unblind_user_id(&self, bucket: &[(Vec<u8>, Vec<u8>)]) -> Option<Uuid> {
        // Get the inverse of both blinding factors
        let scalar1 = self.client_secret.to_nonzero_scalar().invert().unwrap();
        let scalar2 = self.blinding_key.to_nonzero_scalar().invert().unwrap();

        for (blinded_id, blinded_uuid) in bucket {
            // First unblinding of identifier
            let point1 = ProjectivePoint::from_encoded_point(
                &EncodedPoint::from_bytes(blinded_id).ok()?
            ).unwrap() * scalar1;
            
            // Second unblinding of identifier
            let point2 = point1 * scalar2;
            
            // Convert blinded UUID to point
            let uuid_point = ProjectivePoint::from_encoded_point(
                &EncodedPoint::from_bytes(blinded_uuid).ok()?
            ).unwrap();
            
            // Unblind UUID with same scalars
            let unblinded_uuid_point = (uuid_point * scalar1) * scalar2;
            
            // Convert to bytes and try to parse as UUID
            let unblinded_bytes = unblinded_uuid_point.to_affine().to_encoded_point(false).as_bytes();
            if let Ok(uuid) = Uuid::from_slice(&unblinded_bytes[1..17]) {
                return Some(uuid);
            }
        }
        None
    }
}

/// Encodes a UUID to a point on the P-256 curve using a hash-and-try method.
/// This method is not constant-time but is suitable for this use case as the UUID is not secret.
pub fn encode_to_point(user_id: &Uuid) -> AffinePoint {
    let mut hasher = Sha256::new();
    hasher.update(user_id.as_bytes());
    let mut counter = 0u64;

    loop {
        let mut attempt = hasher.clone();
        attempt.update(counter.to_le_bytes());
        let hash = attempt.finalize();

        // Create a compressed point format
        let mut encoded = vec![0x02]; // Start with 0x02 for even Y
        encoded.extend_from_slice(&hash[0..32]); // Take first 32 bytes for X coordinate

        // Try to create a point from the encoded bytes
        if let Some(point) =
            AffinePoint::from_encoded_point(&EncodedPoint::from_bytes(&encoded).unwrap_or_default())
                .into()
        {
            return point;
        }

        counter += 1;
        if counter > 1000 {
            // Add a reasonable limit to prevent infinite loops
            // If we can't find a valid point after 1000 attempts, start with a different initial hash
            hasher = Sha256::new();
            hasher.update(&counter.to_le_bytes());
            hasher.update(user_id.as_bytes());
            counter = 0;
        }
    }
}

/// Hash `b` to a point on the P-256 curve (map data on the curve) using the method in RFC 9380 using SHA-256
fn hash_to_curve(b: u64) -> ProjectivePoint {
    // additional context string in Expand-Message-XMD method helps in domain separation  ensure that distinct inputs to the hash function produce distinct outputs, even if the inputs have the same byte representation. By including this context string, it helps prevent any potential clashes or collisions in the hashing process in the hash function
    NistP256::hash_from_bytes::<ExpandMsgXmd<Sha256>>(&[&b.to_be_bytes()], &[b"rumi"])
        .expect("Should produce a valid point")
}

/// Hash `b` with SHA-256.
pub fn sha256(b: u64) -> [u8; 32] {
    sha2::Sha256::new()
        .chain_update(b.to_be_bytes())
        .finalize()
        .into()
}

// Helper function to get Merkle proof from server
async fn get_merkle_proof_from_server(commitment: &[u8]) -> Result<Vec<u8>, String> {
    let mut client = DiscoveryClient::connect("http://[::1]:50051")
        .await
        .map_err(|e| format!("Failed to connect to server: {}", e))?;
        
    let request = tonic::Request::new(GetMerkleProofRequest {
        commitment: commitment.to_vec(),
    });
    
    let response = client
        .get_merkle_proof(request)
        .await
        .map_err(|e| format!("Failed to get Merkle proof: {}", e))?;
        
    let inner = response.into_inner();
    if !inner.success {
        return Err(inner.message);
    }
    
    Ok(inner.merkle_proof)
}

// Helper function to hash string to curve point
fn hash_to_curve_point(input: &str) -> Result<ProjectivePoint, String> {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let hash = hasher.finalize();
    
    Ok(NistP256::hash_from_bytes::<ExpandMsgXmd<Sha256>>(&[&hash], &[b"rumi"])
        .map_err(|e| format!("Failed to hash to curve: {}", e))?)
}

// Helper function to verify a Merkle proof
fn verify_merkle_proof(commitment: &[u8], proof: &[u8], root: &[u8; 32]) -> Result<bool, String> {
    let proof = MerkleProof::<MerkleHasher>::from_bytes(proof)
        .map_err(|e| format!("Failed to deserialize proof: {}", e))?;
    
    let leaf_hash = MerkleHasher::hash(commitment);
    
    Ok(proof.verify(
        *root,
        &[0], // We don't know the index, but it's not needed for verification
        &[leaf_hash],
        1 << ORAM_DEPTH, // Tree size
    ))
}

// Helper function to get Merkle root from server
async fn get_merkle_root_from_server() -> Result<[u8; 32], String> {
    let mut client = DiscoveryClient::connect("http://[::1]:50051")
        .await
        .map_err(|e| format!("Failed to connect to server: {}", e))?;
        
    let request = tonic::Request::new(GetMerkleRootRequest {});
    
    let response = client
        .get_merkle_root(request)
        .await
        .map_err(|e| format!("Failed to get Merkle root: {}", e))?;
        
    let inner = response.into_inner();
    if !inner.success {
        return Err(inner.message);
    }
    
    let mut root = [0u8; 32];
    root.copy_from_slice(&inner.root);
    Ok(root)
}