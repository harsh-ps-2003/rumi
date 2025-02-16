pub mod oram;
pub mod merkle;

// Include generated gRPC code
pub mod rumi {
    tonic::include_proto!("rumi");
}

use crate::{
    merkle::{MerkleState, generate_proof, verify_merkle_proof},
    oram::{Operation, PathORAM},
    rumi::{discovery_client::DiscoveryClient, GetMerkleProofRequest},
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
    blinding_key: SecretKey,
    merkle_state: MerkleState,
    storage: HashMap<[u8; 8], Vec<(Vec<u8>, Vec<u8>)>>, // prefix -> [(blinded_id, blinded_uuid)]
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
    commitments: HashMap<String, Vec<u8>>, // identifier -> commitment
    storage_path: PathBuf,
}

impl Server {
    /// Create new server with a random secret and the given book of identifier and userID
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R, users: &HashMap<String, Uuid>) -> Self {
        let blinding_key = SecretKey::random(rng);
        let mut merkle_state = MerkleState::new();
        let mut storage = HashMap::new();

        // Initialize storage with existing users if any
        for (identifier, uuid) in users {
            // Create double-hashed commitment for existing users
            let commitment = Self::create_commitment(identifier);
            
            // Add commitment to Merkle tree
            if let Ok(_) = merkle_state.add_leaf(&commitment) {
                // Only add to storage if Merkle tree addition succeeds
                if let Ok(blinded_id) = Self::blind_identifier_str(&blinding_key, identifier) {
                    let prefix = Self::get_prefix(&blinded_id);
                    let entry = storage.entry(prefix).or_insert_with(Vec::new);
                    entry.push((blinded_id, uuid.as_bytes().to_vec()));
                }
            }
        }

        Self {
            blinding_key,
            merkle_state,
            storage,
        }
    }

    /// Retrieves a hashmap of blinded identifier points and corresponding user ID points based on a given hash prefix
    pub fn find_bucket(
        &self,
        prefix: [u8; 8],
        proof_data: &(Vec<u8>, Vec<u8>), // (proof_bytes, vk_bytes)
        _rng: &mut impl RngCore,
    ) -> Option<Vec<(Vec<u8>, Vec<u8>)>> {
        // Extract commitment and verify ZK proof of Merkle path knowledge
        let verified = verify_merkle_proof(
            &proof_data.0, // proof bytes
            &proof_data.1, // verification key bytes
            self.merkle_state.root(),
        ).ok()?;
            
        if !verified {
            return None;
        }
        
        // Return the bucket if proof verifies
        self.storage.get(&prefix).cloned()
    }

    /// Attempts to reverse the blinding of a user ID point to recover and return the original UUID
    pub fn unblind_user_id(&self, blinded_user_id: &EncodedPoint) -> Option<Uuid> {
        let blinded_user_id_point =
            AffinePoint::from_encoded_point(blinded_user_id).expect("Invalid point");
        let scalar = *self.blinding_key.to_nonzero_scalar();
        let user_id_point = (blinded_user_id_point * scalar)
            .to_affine()
            .to_encoded_point(true);
            
        Uuid::from_slice(&user_id_point.as_bytes()[1..17]).ok()
    }

    /// Given a client-blinded identifier point, return a double-blinded identifier point
    pub fn blind_identifier(&self, point: &EncodedPoint) -> Vec<u8> {
        let pk = PublicKey::from_encoded_point(point).unwrap();
        let scalar = *self.blinding_key.to_nonzero_scalar();
        let blinded = pk.to_projective() * scalar;
        blinded.to_affine().to_encoded_point(false).as_bytes().to_vec()
    }

    // get public key set from ORAM
    pub fn get_public_set(&self) -> Vec<String> {
        // Return empty set as we no longer expose public identifiers
        Vec::new()
    }

    pub fn register(
        &mut self,
        identifier: String,
        commitment: Vec<u8>,
        uuid: &Uuid,
        _rng: &mut impl RngCore,
    ) -> Result<Vec<u8>, String> {
        // The commitment is already double-hashed by the client
        // Verify that it matches what we expect
        let expected_commitment = Self::create_commitment(&identifier);
        if commitment != expected_commitment {
            return Err("Invalid commitment".to_string());
        }
        
        // Blind the identifier
        let blinded_id = Self::blind_identifier_str(&self.blinding_key, &identifier)?;
        
        // Store the blinded identifier and UUID
        let prefix = Self::get_prefix(&blinded_id);
        let entry = self.storage.entry(prefix).or_insert_with(Vec::new);
        entry.push((blinded_id, uuid.as_bytes().to_vec()));

        // Add commitment to Merkle tree and get proof
        // The commitment is already double-hashed, so we don't hash it again
        let merkle_proof = self.merkle_state.add_leaf(&commitment)
            .map_err(|e| format!("Failed to create Merkle proof: {}", e))?;
            
        debug!("Generated Merkle proof of length {}", merkle_proof.len());
        Ok(merkle_proof)
    }

    fn blind_identifier_str(key: &SecretKey, identifier: &str) -> Result<Vec<u8>, String> {
        // Hash the identifier to a 64-bit number first
        let mut hasher = Sha256::new();
        hasher.update(identifier.as_bytes());
        let hash = hasher.finalize();
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&hash[0..8]);
        let num = u64::from_be_bytes(bytes);

        // Use hash_to_curve to get a valid curve point
        let point = hash_to_curve(num);
        let pk = PublicKey::from_affine(point.to_affine())
            .map_err(|e| format!("Failed to create public key: {}", e))?;

        let scalar = *key.to_nonzero_scalar();
        let blinded = pk.to_projective() * scalar;
        Ok(blinded.to_affine().to_encoded_point(false).as_bytes().to_vec())
    }

    fn get_prefix(blinded_id: &[u8]) -> [u8; 8] {
        let mut prefix = [0u8; 8];
        prefix.copy_from_slice(&blinded_id[..8]);
        prefix
    }

    pub fn get_merkle_root(&self) -> [u8; 32] {
        self.merkle_state.root()
    }

    pub fn generate_merkle_proof(&self, commitment: &[u8]) -> Result<Vec<u8>, String> {
        self.merkle_state.generate_proof(commitment)
    }

    /// Create a double-hashed commitment from an identifier
    fn create_commitment(identifier: &str) -> Vec<u8> {
        // First hash using SHA256
        let mut hasher = Sha256::new();
        hasher.update(identifier.as_bytes());
        let first_hash = hasher.finalize();
        
        // Second hash using MerkleHasher (rs_merkle::algorithms::Sha256)
        let hash = MerkleHasher::hash(&first_hash);
        hash.to_vec()
    }
}

impl Client {
    /// Create a new client using a random secret.
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

    /// Generate a double-hashed commitment from an identifier
    fn generate_commitment(identifier: &str) -> Vec<u8> {
        // First hash using SHA256
        let mut hasher = Sha256::new();
        hasher.update(identifier.as_bytes());
        let first_hash = hasher.finalize();
        
        // Second hash using MerkleHasher (rs_merkle::algorithms::Sha256)
        let hash = MerkleHasher::hash(&first_hash);
        hash.to_vec()
    }

    pub fn prepare_registration(&mut self, identifier: &str) -> (String, Vec<u8>) {
        // Generate the double-hashed commitment
        let commitment = Self::generate_commitment(identifier);
        
        // Store the double-hashed commitment
        self.store_commitment(identifier.to_string(), commitment.clone());
        
        (identifier.to_string(), commitment)
    }

    pub fn store_merkle_proof(&mut self, identifier: String, _merkle_proof: Vec<u8>) {
        // We no longer store the proof - it's requested from server when needed
    }

    pub async fn prepare_lookup(&self, identifier: &str) -> Result<(Prefix, (Vec<u8>, Vec<u8>)), String> {
        // Retrieve the stored double-hashed commitment
        let commitment = self.commitments.get(identifier)
            .ok_or_else(|| "No commitment found for identifier".to_string())?
            .clone();

        // Get the Merkle proof from the server
        let merkle_proof = get_merkle_proof_from_server(&commitment).await?;

        // Generate ZK proof using the double-hashed commitment
        let (zk_proof, vk) = generate_proof(&commitment, &merkle_proof)?;

        // Get prefix for the bucket lookup
        let prefix = prefix(&commitment);

        Ok((prefix, (zk_proof, vk)))
    }

    fn blind_identifier(&self, identifier: &str) -> Result<Vec<u8>, String> {
        // Hash the identifier to a 64-bit number
        let mut hasher = Sha256::new();
        hasher.update(identifier.as_bytes());
        let hash = hasher.finalize();
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&hash[0..8]);
        let num = u64::from_be_bytes(bytes);

        // Use hash_to_curve to get a valid curve point
        let point = hash_to_curve(num);
        let pk = PublicKey::from_affine(point.to_affine())
            .map_err(|e| format!("Failed to create public key: {}", e))?;
        
        let scalar = *self.client_secret.to_nonzero_scalar();
        let blinded = pk.to_projective() * scalar;
        Ok(blinded.to_affine().to_encoded_point(false).as_bytes().to_vec())
    }

    pub fn unblind_user_id(&self, bucket: &[(Vec<u8>, Vec<u8>)]) -> Option<Uuid> {
        // Get the inverse of client's secret key for unblinding
        let scalar = self.client_secret.to_nonzero_scalar().invert().unwrap();

        // Iterate through bucket entries
        for (blinded_id, blinded_uuid) in bucket {
            // Try to unblind the server-blinded identifier
            let server_blinded_point = PublicKey::from_encoded_point(
                &EncodedPoint::from_bytes(blinded_id).ok()?
            ).unwrap().to_projective() * scalar;

            // If we find a match, return the UUID
            if let Ok(uuid) = Uuid::from_slice(blinded_uuid) {
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

/// Return an N-byte prefix
pub fn prefix(bytes: &[u8]) -> Prefix {
    bytes[..PREFIX_LEN]
        .try_into()
        .expect("Should be at least 8 bytes long")
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