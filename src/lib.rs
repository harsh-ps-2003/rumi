mod oram;

use crate::oram::{Operation, PathORAM};
use generic_array::GenericArray;
use p256::{
    elliptic_curve::{
        hash2curve::{ExpandMsgXmd, FromOkm, GroupDigest},
        ops::ReduceNonZero,
        sec1::{self, FromEncodedPoint, ToEncodedPoint},
        Field,
    },
    AffinePoint,  // point satisfying the curve
    EncodedPoint, // compact representation of a point on curve for storing
    NistP256,
    ProjectivePoint, // alternative representation of a point on curve for simplifying calculations
    Scalar,          // element of the finite field over which the elliptic curve
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

/// A fixed-size prefix of an SHA-256 hash.
pub type Prefix = [u8; PREFIX_LEN];
// for truncation of hashed_identifier
const PREFIX_LEN: usize = 8;

#[derive(Serialize, Deserialize)]
struct ORAMBlock {
    blinded_identifier: EncodedPoint,
    blinded_user_id: EncodedPoint,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZKSMProof {
    commitment: EncodedPoint,
    challenge: Scalar,
    response: Scalar,
}

#[derive(Debug)]
pub struct Server {
    server_secret: Scalar,
    oram: PathORAM,
}

pub struct Client {
    client_secret: Scalar,
}

impl Server {
    /// Create new server with a random secret and the given book of identifier and userID
    pub fn new(rng: &mut (impl CryptoRng + RngCore), users: &HashMap<u64, Uuid>) -> Server {
        let mut rng = rng;
        let server_secret = Scalar::random(&mut rng);
        let mut oram = PathORAM::new();

        for (&identifier, user_id) in users {
            let hashed_identifier = sha256(identifier);
            let blinded_identifier_point = hash_to_curve(identifier) * server_secret;
            let user_id_point = encode_to_point(user_id);
            let blinded_user_id = user_id_point
                * server_secret
                * Scalar::reduce_nonzero_bytes(&hashed_identifier.into());

            let block = ORAMBlock {
                blinded_identifier: blinded_identifier_point.to_affine().to_encoded_point(true),
                blinded_user_id: blinded_user_id.to_affine().to_encoded_point(true),
            };

            oram.access(
                Operation::Write,
                identifier,
                Some(bincode::serialize(&block).unwrap()),
                &mut rng,
            );
        }

        Server {
            server_secret,
            oram,
        }
    }

    /// Retrieves a hashmap of blinded identifier points and corresponding user ID points based on a given hash prefix
    pub fn find_bucket(
        &mut self,
        hashprefix: Prefix,
        zksm_proof: &ZKSMProof,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Option<HashMap<EncodedPoint, EncodedPoint>> {
        if !self.verify_zksm_proof(zksm_proof) {
            return None;
        }

        let mut result = HashMap::new();
        let mut zeroizing_buffer = Zeroizing::new(Vec::new());

        // Perform a fixed number of accesses regardless of actual number of matches
        const FIXED_ACCESSES: usize = 1000;
        // Maximum delay in milliseconds
        const MAX_DELAY_MS: u64 = 10;

        for _ in 0..FIXED_ACCESSES {
            let id = rng.next_u64(); // Random ID for each access for making it more difficult to guess the number of matches
            let is_real_access = prefix(&sha256(id)) == hashprefix;

            // Explicitly zeroizes the buffer before each use to ensure no sensitive data leaks between accesses.
            if let Some(data) = self.oram.access(Operation::Read, id, None, rng) {
                zeroizing_buffer.zeroize();
                zeroizing_buffer.extend_from_slice(&data);

                if is_real_access {
                    if let Ok(block) = bincode::deserialize::<ORAMBlock>(&zeroizing_buffer) {
                        result.insert(block.blinded_identifier, block.blinded_user_id);
                    }
                }
            }

            // Perform a dummy write to mask the operation type
            let dummy_data = vec![0u8; 64]; // Adjust size as needed
            self.oram
                .access(Operation::Write, rng.next_u64(), Some(dummy_data), rng);

            // Add a random delay
            std::thread::sleep(std::time::Duration::from_millis(
                rng.next_u64() % MAX_DELAY_MS,
            ));
        }

        Some(result)
    }

    /// Attempts to reverse the blinding of a user ID point to recover and return the original UUID
    pub fn unblind_user_id(&self, blinded_user_id: &EncodedPoint) -> Option<Uuid> {
        // Un-blind the double blinded point, giving us the server's point for this identifier.
        let blinded_user_id_point =
            AffinePoint::from_encoded_point(blinded_user_id).expect("Invalid point");
        let user_id_point = (blinded_user_id_point
            * self.server_secret.invert().expect("Should be invertible"))
        .to_encoded_point(true);
        Uuid::from_slice(&user_id_point.as_bytes()[1..17]).ok()
    }

    /// Given a client-blinded identifier point, return a double-blinded identifier point
    pub fn blind_identifier(&self, client_blinded_identifier_point: &EncodedPoint) -> EncodedPoint {
        let client_blinded_identifier_point =
            AffinePoint::from_encoded_point(client_blinded_identifier_point)
                .expect("Invalid point");
        (client_blinded_identifier_point * self.server_secret)
            .to_affine()
            .to_encoded_point(true)
    }

    // Add this new method to get the public set from ORAM
    pub fn get_public_set(&self) -> Vec<u64> {
        self.oram.get_all_identifiers()
    }

    // Add this new method to verify ZKSM proof
    fn verify_zksm_proof(&self, proof: &ZKSMProof) -> bool {
        let public_set = self.get_public_set();
        verify_zksm_proof(&public_set, proof)
    }
}

impl Client {
    /// Create a new client using a random secret.
    pub fn new(rng: impl CryptoRng + RngCore) -> Client {
        Client {
            client_secret: Scalar::random(rng),
        }
    }

    /// Generates a blinded identifier point by:
    /// Hashing the identifier
    /// Blinding the hash using the client's secret
    /// Returning the hash prefix and the blinded identifier point
    pub fn request_identifier(
        &self,
        identifier: u64,
        public_set: &[u64],
    ) -> (Prefix, EncodedPoint, ZKSMProof) {
        let hashed_identifier = sha256(identifier);
        let client_blinded_identifier_point = hash_to_curve(identifier) * self.client_secret;
        let zksm_proof = generate_zksm_proof(identifier, public_set);

        (
            prefix(&hashed_identifier),
            client_blinded_identifier_point
                .to_affine()
                .to_encoded_point(true),
            zksm_proof,
        )
    }

    /// Attempts to un-blind a double-blinded identifier point to find and return the corresponding user ID point from a given bucket
    pub fn find_user_id(
        &self,
        double_blinded_identifier_point: &EncodedPoint,
        bucket: &HashMap<EncodedPoint, EncodedPoint>,
        identifier: u64,
    ) -> Option<EncodedPoint> {
        // Un-blind the double-blinded point, giving us the server's point for this identifier
        let double_blinded_identifier_point =
            AffinePoint::from_encoded_point(double_blinded_identifier_point)
                .expect("Invalid point");
        let server_phone_point = (double_blinded_identifier_point
            * self.client_secret.invert().expect("Should be invertible"))
        .to_encoded_point(true);

        // Use it to find the user ID point, if any
        if let Some(blinded_user_id) = bucket.get(&server_phone_point).cloned() {
            // Hash the identifier and reduce it to a scalar.
            let hashed_identifier_scalar = Scalar::reduce_nonzero_bytes(&sha256(identifier).into());

            // Un-blind the user ID point
            let blinded_user_id_point =
                AffinePoint::from_encoded_point(&blinded_user_id).expect("Invalid point");
            let unblinded_user_id_point = blinded_user_id_point
                * hashed_identifier_scalar
                    .invert()
                    .expect("Should be invertible");

            // Return
            Some(unblinded_user_id_point.to_affine().to_encoded_point(true))
        } else {
            None
        }
    }
}

/// Encodes a UUID to a point on the P-256 curve using a hash-and-try method.
/// This method is not constant-time but is suitable for this use case as the UUID is not secret.
fn encode_to_point(user_id: &Uuid) -> AffinePoint {
    let mut hasher = Sha256::new();
    hasher.update(user_id.as_bytes());
    let mut counter = 0u64;

    loop {
        let mut attempt = hasher.clone();
        attempt.update(counter.to_le_bytes());
        let hash = attempt.finalize();

        if let Some(point) = AffinePoint::from_encoded_point(&EncodedPoint::from_bytes(&hash).unwrap()).into() {
            return point;
        }

        counter += 1;
    }
}

/// Hash `b` to a point on the P-256 curve (map data on the curve) using the method in RFC 9380 using SHA-256
fn hash_to_curve(b: u64) -> ProjectivePoint {
    // additional context string in Expand-Message-XMD method helps in domain separation  ensure that distinct inputs to the hash function produce distinct outputs, even if the inputs have the same byte representation. By including this context string, it helps prevent any potential clashes or collisions in the hashing process in the hash function
    NistP256::hash_from_bytes::<ExpandMsgXmd<Sha256>>(&[&b.to_be_bytes()], &[b"rumi"])
        .expect("Should produce a valid point")
}

/// Hash `b` with SHA-256.
fn sha256(b: u64) -> [u8; 32] {
    sha2::Sha256::new()
        .chain_update(b.to_be_bytes())
        .finalize()
        .into()
}

/// Return an N-byte prefix
fn prefix(bytes: &[u8]) -> Prefix {
    bytes[..PREFIX_LEN]
        .try_into()
        .expect("Should be at least 8 bytes long")
}

// Add these new functions for ZKSM proof generation and verification
fn generate_zksm_proof(identifier: u64, public_set: &[u64]) -> ZKSMProof {
    let mut rng = rand::thread_rng();
    let r = Scalar::random(&mut rng);
    let commitment = hash_to_curve(identifier) * r;

    // Challenge should be derived from the commitment and public parameters
    let challenge = hash_to_scalar(
        &[
            commitment.to_affine().to_encoded_point(true).as_bytes(),
            &serialize_public_set(public_set),
        ]
        .concat(),
    );
    let response = r + Scalar::from(identifier) * challenge;

    ZKSMProof {
        commitment: commitment.to_affine().to_encoded_point(true),
        challenge,
        response,
    }
}

fn verify_zksm_proof(public_set: &[u64], proof: &ZKSMProof) -> bool {
    let commitment_point = AffinePoint::from_encoded_point(&proof.commitment).unwrap();
    let challenge = hash_to_scalar(
        &[
            proof.commitment.as_bytes(),
            &serialize_public_set(public_set),
        ]
        .concat(),
    );

    // Check if the proof is valid for any element in the public set
    public_set.iter().any(|&x| {
        let lhs = ProjectivePoint::from(commitment_point) + hash_to_curve(x) * proof.challenge;
        let rhs = hash_to_curve(x) * proof.response;
        lhs.to_affine() == rhs.to_affine()
    })
}

// Helper function to hash to a scalar
fn hash_to_scalar(data: &[u8]) -> Scalar {
    let hash = sha2::Sha256::digest(data);
    let array = GenericArray::from_slice(hash.as_slice());
    Scalar::from_okm(array)
}

// Helper function to serialize the public set
fn serialize_public_set(public_set: &[u64]) -> Vec<u8> {
    public_set.iter().flat_map(|&x| x.to_le_bytes()).collect()
}
