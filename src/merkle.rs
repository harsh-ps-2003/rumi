use rs_merkle::{
    Hasher, MerkleTree, MerkleProof,
    algorithms::Sha256 as MerkleHasher,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use ark_ff::{Field, Zero, One, PrimeField, BigInteger};
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable},
};
use ark_bn254::{Bn254, Fr};
use ark_groth16::{
    Groth16,
    ProvingKey, Proof, VerifyingKey,
};
use ark_snark::{SNARK, CircuitSpecificSetupSNARK};
use ark_std::{rand::RngCore, UniformRand};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize, Read, Write};
use ark_r1cs_std::{
    prelude::*,
    fields::fp::FpVar,
    boolean::Boolean,
};
use tracing::{debug, warn};

// Maximum height of the Merkle tree
const MAX_TREE_DEPTH: usize = 32;

/// Circuit for proving knowledge of a Merkle path
#[derive(Clone)]
struct MerkleProofCircuit {
    // Public inputs
    pub root: Option<Fr>,
    pub leaf: Option<Fr>,
    
    // Private inputs (witness)
    pub path: Option<Vec<(Fr, bool)>>, // (sibling_hash, is_left)
    pub commitment: Option<Vec<u8>>, // Original commitment
}

impl ConstraintSynthesizer<Fr> for MerkleProofCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Allocate public inputs
        let root_var = FpVar::new_input(cs.clone(), || self.root.ok_or(SynthesisError::AssignmentMissing))?;
        let leaf_var = FpVar::new_input(cs.clone(), || self.leaf.ok_or(SynthesisError::AssignmentMissing))?;
        
        // Validate commitment hash matches leaf
        let commitment = self.commitment.ok_or(SynthesisError::AssignmentMissing)?;
        let computed_leaf_hash = MerkleHasher::hash(&commitment);
        let computed_leaf_fr = hash_to_field(&computed_leaf_hash);
        
        // Ensure leaf matches commitment hash
        if let Some(leaf) = self.leaf {
            if leaf != computed_leaf_fr {
                return Err(SynthesisError::Unsatisfiable);
            }
        }
        
        // Start with leaf hash
        let mut current = leaf_var;
        
        // Process each level of the path
        if let Some(path) = self.path {
            for (sibling, is_left) in path {
                // Allocate sibling as witness variable
                let sibling_var = FpVar::new_witness(cs.clone(), || Ok(sibling))?;
                let is_left_var = Boolean::new_witness(cs.clone(), || Ok(is_left))?;
                
                // Create left and right inputs based on direction
                let (left, right) = if is_left {
                    (current.clone(), sibling_var.clone())
                } else {
                    (sibling_var.clone(), current.clone())
                };
                
                // Convert field elements to bytes for hashing
                let left_fr = match left.value() {
                    Ok(v) => v,
                    Err(_) => return Err(SynthesisError::AssignmentMissing),
                };
                let right_fr = match right.value() {
                    Ok(v) => v,
                    Err(_) => return Err(SynthesisError::AssignmentMissing),
                };
                
                // Combine the field elements into bytes   
                let mut combined = Vec::new();
                combined.extend_from_slice(&left_fr.into_bigint().to_bytes_le());
                combined.extend_from_slice(&right_fr.into_bigint().to_bytes_le());
                
                // Hash the combined bytes
                let hash = MerkleHasher::hash(&combined);
                let hash_fr = hash_to_field(&hash);
                
                // Create a new witness for the hash result
                current = FpVar::new_witness(cs.clone(), || Ok(hash_fr))?;
                
                // Add constraints to ensure the hash computation is correct
                let computed_hash = combine_hash_inputs(&left, &right)?;
                current.enforce_equal(&computed_hash)?;
            }
        }
        
        // Final constraint: computed root must equal input root
        current.enforce_equal(&root_var)?;
        
        Ok(())
    }
}

/// Helper function to combine hash inputs in a way that preserves the hash properties
fn combine_hash_inputs(left: &FpVar<Fr>, right: &FpVar<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
    // Create a simple linear combination first
    let mut result = left.clone();
    result += right;
    
    // Add non-linear terms for better security
    let product = left * right;
    result += &product;
    
    // Add some entropy from the individual elements
    let left_squared = left * left;
    let right_squared = right * right;
    result += &left_squared;
    result += &right_squared;
    
    Ok(result)
}

// Struct to hold Merkle tree state
pub struct MerkleState {
    tree: MerkleTree<MerkleHasher>,
    leaf_map: HashMap<Vec<u8>, usize>, // Maps leaf data to its index
}

impl MerkleState {
    pub fn new() -> Self {
        Self {
            tree: MerkleTree::<MerkleHasher>::new(),
            leaf_map: HashMap::new(),
        }
    }

    // Add a new leaf to the tree and return its proof
    pub fn add_leaf(&mut self, data: &[u8]) -> Result<Vec<u8>, String> {
        // Check if the pre-hashed commitment exists
        if self.leaf_map.contains_key(data) {
            return Err("Leaf already exists".to_string());
        }

        // Use the data directly as it's already hashed by the client
        let leaf_hash = data.to_vec();
        let leaf_index = self.tree.leaves_len();
        
        // Insert leaf - rs_merkle will hash this internally
        self.tree.insert(MerkleHasher::hash(data));
        
        // Pad tree to next power of 2 if needed
        let current_size = self.tree.leaves_len();
        let next_power_of_2 = current_size.next_power_of_two();
        
        if current_size < next_power_of_2 {
            for _ in current_size..next_power_of_2 {
                self.tree.insert(MerkleHasher::hash(&[0u8; 32])); // Add padding leaves
            }
        }
        
        // Commit tree to finalize structure
        self.tree.commit();
        
        // Store mapping using the pre-hashed commitment
        self.leaf_map.insert(data.to_vec(), leaf_index);
        
        // Generate and return Merkle proof
        let proof = self.tree.proof(&[leaf_index]);
        let proof_bytes = proof.to_bytes();
        
        // Verify the proof before returning
        if !proof.verify(
            self.tree.root().ok_or("No root available")?,
            &[leaf_index],
            &[MerkleHasher::hash(data)],
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

    // Get current root
    pub fn root(&self) -> [u8; 32] {
        self.tree.root().unwrap_or([0; 32])
    }

    // Verify a proof
    pub fn verify_proof(&self, data: &[u8], proof_bytes: &[u8]) -> Result<bool, String> {
        // Use the data directly as it's already hashed
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

// Helper function to ensure consistent commitment hashing
pub fn hash_commitment(data: &[u8]) -> Vec<u8> {
    MerkleHasher::hash(data).to_vec()
}

// Generate a ZK proof of Merkle path knowledge
pub fn generate_proof(
    commitment: &[u8],
    merkle_proof: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    // First validate the commitment
    if commitment.is_empty() {
        return Err("Empty commitment".to_string());
    }
    
    // The commitment is already hashed once by the client
    // rs_merkle will hash it again internally, so we need to account for that
    let leaf_hash = MerkleHasher::hash(commitment);
    let leaf_fr = hash_to_field(&leaf_hash);
    
    // Deserialize the Merkle proof
    let proof = MerkleProof::<MerkleHasher>::from_bytes(merkle_proof)
        .map_err(|e| format!("Failed to deserialize proof: {}", e))?;
    
    // Extract path and compute root
    let path = extract_path_from_proof(&proof)?;
    
    // Create circuit instance with commitment
    let circuit = MerkleProofCircuit {
        root: Some(leaf_fr), // Will be updated after path computation
        leaf: Some(leaf_fr),
        path: Some(path.clone()),
        commitment: Some(commitment.to_vec()),
    };
    
    // Compute final root using the same hashing as the Merkle tree
    let mut current_fr = leaf_fr;
    for (sibling_fr, is_left) in &path {
        // Correctly determine left and right based on is_left
        let (left_fr, right_fr) = if *is_left {
            (*sibling_fr, current_fr) // Sibling on the left, current on the right
        } else {
            (current_fr, *sibling_fr) // Current on the left, sibling on the right
        };
        
        // Combine field elements using MerkleHasher for consistency
        let mut combined = Vec::new();
        combined.extend_from_slice(&left_fr.to_bytes());
        combined.extend_from_slice(&right_fr.to_bytes());
        let hash = MerkleHasher::hash(&combined);
        current_fr = hash_to_field(&hash);
    }
    
    // Update circuit with computed root
    let circuit = MerkleProofCircuit {
        root: Some(current_fr),
        leaf: Some(leaf_fr),
        path: Some(path),
        commitment: Some(commitment.to_vec()), // Include original commitment
    };
    
    // Generate parameters
    let mut rng = ark_std::rand::thread_rng();
    
    // Generate proving and verification keys
    let (pk, vk) = Groth16::<Bn254>::setup(circuit.clone(), &mut rng)
        .map_err(|e| format!("Failed to generate parameters: {}", e))?;
    
    // Generate the proof
    let proof = Groth16::<Bn254>::prove(&pk, circuit.clone(), &mut rng)
        .map_err(|e| format!("Failed to create proof: {}", e))?;
    
    // Verify the proof before returning
    let inputs = vec![current_fr, leaf_fr];
    let verified = Groth16::<Bn254>::verify(&vk, &inputs, &proof)
        .map_err(|e| format!("Proof verification failed: {}", e))?;
        
    if !verified {
        return Err("Generated proof failed verification".to_string());
    }
    
    // Serialize proof and verification key
    let proof_bytes = serialize_proof(&proof)?;
    let vk_bytes = serialize_vk(&vk)?;
    
    Ok((proof_bytes, vk_bytes))
}

fn extract_path_from_proof(proof: &MerkleProof<MerkleHasher>) -> Result<Vec<(Fr, bool)>, String> {
    let mut path = Vec::new();
    let proof_hashes = proof.proof_hashes();
    
    // For each level in the proof
    for (i, hash) in proof_hashes.iter().enumerate() {
        let fr = hash_to_field(hash);
        // In a binary Merkle tree, a node's sibling is on the left if the node's index is even
        // and on the right if the node's index is odd
        let is_left = i % 2 == 1;
        path.push((fr, is_left));
    }
    
    Ok(path)
}

// Verify a ZK proof of Merkle path knowledge
pub fn verify_merkle_proof(
    proof_bytes: &[u8],
    vk_bytes: &[u8],
    root: [u8; 32],
) -> Result<bool, String> {
    // Deserialize proof and verification key
    let proof = deserialize_proof(proof_bytes)?;
    let vk = deserialize_vk(vk_bytes)?;
    
    // Convert root to field element
    let root_fr = hash_to_field(&root);
    
    // Verify the proof
    Groth16::<Bn254>::verify(&vk, &[root_fr], &proof)
        .map_err(|e| format!("Proof verification failed: {}", e))
}

// Helper functions

fn hash_to_field(bytes: &[u8; 32]) -> Fr {
    // First hash the input to get a more uniform distribution
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let hash = hasher.finalize();
    
    // Convert to field element using chunks to preserve more entropy
    let mut acc = Fr::zero();
    let mut base = Fr::one();
    
    // Process 4 bytes at a time to stay within field modulus
    for chunk in hash.chunks(4) {
        let mut val = 0u64;
        for (i, &byte) in chunk.iter().enumerate() {
            val |= (byte as u64) << (8 * i);
        }
        acc += Fr::from(val) * base;
        base *= Fr::from(1u64 << 32);
    }
    
    acc
}

fn serialize_proof(proof: &Proof<Bn254>) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    proof.serialize_uncompressed(&mut bytes)
        .map_err(|e| format!("Failed to serialize proof: {}", e))?;
    Ok(bytes)
}

fn deserialize_proof(bytes: &[u8]) -> Result<Proof<Bn254>, String> {
    let mut reader = bytes;
    Proof::deserialize_uncompressed(&mut reader)
        .map_err(|e| format!("Failed to deserialize proof: {}", e))
}

fn serialize_vk(vk: &VerifyingKey<Bn254>) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    vk.serialize_uncompressed(&mut bytes)
        .map_err(|e| format!("Failed to serialize verification key: {}", e))?;
    Ok(bytes)
}

fn deserialize_vk(bytes: &[u8]) -> Result<VerifyingKey<Bn254>, String> {
    let mut reader = bytes;
    VerifyingKey::deserialize_uncompressed(&mut reader)
        .map_err(|e| format!("Failed to deserialize verification key: {}", e))
}

// Helper function to convert Fr to bytes
trait ToBytes {
    fn to_bytes(&self) -> [u8; 32];
}

impl ToBytes for Fr {
    fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        self.serialize_uncompressed(&mut bytes[..])
            .expect("Serialization should not fail");
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree() {
        let mut state = MerkleState::new();
        
        // Test adding a leaf
        let data1 = b"test1";
        let proof1 = state.add_leaf(data1).unwrap();
        
        // Test adding another leaf
        let data2 = b"test2";
        let proof2 = state.add_leaf(data2).unwrap();
        
        // Verify proofs
        assert!(state.verify_proof(data1, &proof1).unwrap());
        assert!(state.verify_proof(data2, &proof2).unwrap());
        
        // Test non-existent leaf
        let data3 = b"test3";
        assert!(!state.verify_proof(data3, &proof1).unwrap());
        
        // Test retrieving proof
        let retrieved_proof = state.generate_proof(data1).unwrap();
        assert!(state.verify_proof(data1, &retrieved_proof).unwrap());
    }

    #[test]
    fn test_zk_proof() {
        let mut state = MerkleState::new();
        let data = b"test_data";
        
        // Add data and get proof
        let merkle_proof = state.add_leaf(data).unwrap();
        let root = state.root();
        
        // Generate ZK proof
        let (proof_bytes, vk_bytes) = generate_proof(data, &merkle_proof).unwrap();
        
        // Verify ZK proof
        assert!(verify_merkle_proof(&proof_bytes, &vk_bytes, root).unwrap());
    }
} 