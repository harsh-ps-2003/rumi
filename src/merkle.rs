use rs_merkle::{
    Hasher, MerkleTree, MerkleProof,
    algorithms::Sha256 as MerkleHasher,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use p256::{
    elliptic_curve::{
        hash2curve::{ExpandMsgXmd, FromOkm, GroupDigest},
        ops::ReduceNonZero,
        sec1::{self, FromEncodedPoint, ToEncodedPoint},
        Field, Scalar,
    },
    AffinePoint,
    EncodedPoint,
    NistP256,
    ProjectivePoint,
    PublicKey,
    SecretKey,
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

// Schnorr-like proof for set membership
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SetMembershipProof {
    commitment: Vec<u8>,     // Commitment to the identifier
    challenge: Vec<u8>,      // Challenge from Fiat-Shamir
    response: Vec<u8>,       // Response to prove knowledge
}

pub struct MerkleState {
    tree: MerkleTree<MerkleHasher>,
    leaf_map: HashMap<Vec<u8>, usize>,
}

impl MerkleState {
    pub fn new() -> Self {
        Self {
            tree: MerkleTree::<MerkleHasher>::new(),
            leaf_map: HashMap::new(),
        }
    }

    pub fn add_leaf(&mut self, data: &[u8]) -> Result<Vec<u8>, String> {
        // Check if the commitment exists
        if self.leaf_map.contains_key(data) {
            return Err("Leaf already exists".to_string());
        }

        // Hash the data consistently
        let leaf_hash = MerkleHasher::hash(data);
        let leaf_index = self.tree.leaves_len();
        
        // Insert leaf with the same hash
        self.tree.insert(leaf_hash);
        
        // Pad tree to next power of 2 if needed
        let current_size = self.tree.leaves_len();
        let next_power_of_2 = current_size.next_power_of_two();
        
        if current_size < next_power_of_2 {
            for _ in current_size..next_power_of_2 {
                self.tree.insert(MerkleHasher::hash(&[0u8; 32]));
            }
        }
        
        // Commit tree to finalize structure
        self.tree.commit();
        
        // Store mapping using the original data
        self.leaf_map.insert(data.to_vec(), leaf_index);
        
        // Generate and return Merkle proof
        let proof = self.tree.proof(&[leaf_index]);
        let proof_bytes = proof.to_bytes();
        
        // Verify the proof before returning
        if !proof.verify(
            self.tree.root().ok_or("No root available")?,
            &[leaf_index],
            &[leaf_hash],
            self.tree.leaves_len(),
        ) {
            return Err("Generated invalid Merkle proof".to_string());
        }
        
        debug!("Generated valid Merkle proof of length {} for leaf index {}", proof_bytes.len(), leaf_index);
        Ok(proof_bytes)
    }

    pub fn generate_proof(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        // Use the pre-hashed commitment for lookup
        if let Some(&index) = self.leaf_map.get(data) {
            let proof = self.tree.proof(&[index]);
            Ok(proof.to_bytes())
        } else {
            Err("Leaf not found".to_string())
        }
    }

    pub fn root(&self) -> [u8; 32] {
        self.tree.root().unwrap_or([0; 32])
    }

    pub fn verify_proof(&self, data: &[u8], proof_bytes: &[u8]) -> Result<bool, String> {
        let leaf_hash = MerkleHasher::hash(data);
        let proof = MerkleProof::<MerkleHasher>::from_bytes(proof_bytes)
            .map_err(|e| format!("Failed to deserialize proof: {}", e))?;
        
        if let Some(&index) = self.leaf_map.get(data) {
            Ok(proof.verify(
                self.tree.root().ok_or("No root available")?,
                &[index],
                &[leaf_hash],
                self.tree.leaves_len(),
            ))
        } else {
            Ok(false)
        }
    }
}

// Generate a Schnorr-like proof of set membership
pub fn generate_proof(
    commitment: &[u8],
    merkle_proof: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    // First validate the commitment
    if commitment.is_empty() {
        return Err("Empty commitment".to_string());
    }
    
    // Generate random scalar for blinding
    let mut rng = rand::thread_rng();
    let blinding = SecretKey::random(&mut rng);
    let blinding_point = blinding.to_projective();
    
    // Create commitment point
    let commitment_point = hash_to_curve_point(commitment)?;
    
    // Create challenge using Fiat-Shamir
    let mut hasher = Sha256::new();
    hasher.update(&commitment);
    hasher.update(&merkle_proof);
    hasher.update(&blinding_point.to_affine().to_encoded_point(true).as_bytes());
    let challenge = hasher.finalize();
    
    // Convert challenge to scalar
    let challenge_scalar = scalar_from_bytes(&challenge);
    
    // Generate response
    let response = blinding.to_nonzero_scalar() + (challenge_scalar * commitment_point.to_affine().coordinates().x_coord().unwrap());
    
    // Create proof
    let proof = SetMembershipProof {
        commitment: commitment.to_vec(),
        challenge: challenge.to_vec(),
        response: response.to_bytes_be().to_vec(),
    };
    
    // Serialize proof
    let mut proof_bytes = Vec::new();
    bincode::serialize_into(&mut proof_bytes, &proof)
        .map_err(|e| format!("Failed to serialize proof: {}", e))?;
    
    // Create verification key (public parameters)
    let vk = commitment_point.to_affine().to_encoded_point(true).as_bytes().to_vec();
    
    Ok((proof_bytes, vk))
}

// Verify a Schnorr-like proof of set membership
pub fn verify_set_membership_proof(
    proof_bytes: &[u8],
    vk_bytes: &[u8],
    root: [u8; 32],
) -> Result<bool, String> {
    // Deserialize proof
    let proof: SetMembershipProof = bincode::deserialize(proof_bytes)
        .map_err(|e| format!("Failed to deserialize proof: {}", e))?;
    
    // Reconstruct commitment point
    let commitment_point = hash_to_curve_point(&proof.commitment)?;
    
    // Verify commitment point matches verification key
    let vk_point = ProjectivePoint::from_encoded_point(
        &EncodedPoint::from_bytes(vk_bytes)
            .map_err(|e| format!("Invalid verification key: {}", e))?
    ).unwrap();
    
    if commitment_point != vk_point {
        return Ok(false);
    }
    
    // Convert challenge and response to scalars
    let challenge = scalar_from_bytes(&proof.challenge);
    let response = Scalar::from_bytes_be(&proof.response)
        .map_err(|e| format!("Invalid response: {}", e))?;
    
    // Verify the proof
    let lhs = ProjectivePoint::generator() * response;
    let rhs = commitment_point * challenge;
    
    Ok(lhs == rhs)
}

// Helper function to convert bytes to scalar
fn scalar_from_bytes(bytes: &[u8]) -> Scalar<NistP256> {
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&bytes[..32]);
    Scalar::from_bytes_be(&scalar_bytes).unwrap_or_else(|_| Scalar::zero())
}

// Helper function to hash bytes to curve point
fn hash_to_curve_point(bytes: &[u8]) -> Result<ProjectivePoint, String> {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let hash = hasher.finalize();
    
    Ok(NistP256::hash_from_bytes::<ExpandMsgXmd<Sha256>>(&[&hash], &[b"rumi"])
        .map_err(|e| format!("Failed to hash to curve: {}", e))?)
} 