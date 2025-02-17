use p256::EncodedPoint;
use tokio::sync::oneshot;
use uuid::Uuid;
use crate::ZKSMProof;
use std::collections::HashMap;

/// Response types for each operation
pub type PublicSetResponse = Vec<u64>;
pub type FindResponse = Option<(Vec<u8>, Vec<(Vec<u8>, Vec<u8>)>)>;
pub type RegisterResponse = Result<(), &'static str>;

/// Messages that can be sent to the ServerActor
#[derive(Debug)]
pub enum ServerMessage {
    /// Get the public set of identifiers
    GetPublicSet {
        response: oneshot::Sender<PublicSetResponse>,
    },
    /// Find a user by their identifier
    Find {
        prefix: [u8; 8],
        client_blinded_identifier: Vec<u8>,
        zksm_proof: String,
        response: oneshot::Sender<FindResponse>,
    },
    /// Register a new user
    Register {
        identifier: u64,
        uuid: Uuid,
        response: oneshot::Sender<RegisterResponse>,
    },
} 