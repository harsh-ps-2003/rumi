use crate::{Server, ZKSMProof};
use crate::messages::{ServerMessage, PublicSetResponse, FindResponse, RegisterResponse};
use p256::EncodedPoint;
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;
use tracing::{debug, error, info};
use serde_json;

/// Handle to communicate with the ServerActor
#[derive(Clone, Debug)]
pub struct ServerHandle {
    sender: mpsc::Sender<ServerMessage>,
}

impl ServerHandle {
    /// Create a new ServerHandle
    pub fn new(sender: mpsc::Sender<ServerMessage>) -> Self {
        Self { sender }
    }

    /// Get the public set of identifiers
    pub async fn get_public_set(&self) -> PublicSetResponse {
        let (send, recv) = oneshot::channel();
        let msg = ServerMessage::GetPublicSet { response: send };
        
        self.sender.send(msg).await.expect("Actor task has been killed");
        recv.await.expect("Actor task has been killed")
    }

    /// Find a user by their identifier
    pub async fn find(
        &self,
        prefix: [u8; 8],
        client_blinded_identifier: Vec<u8>,
        zksm_proof: String,
    ) -> FindResponse {
        let (send, recv) = oneshot::channel();
        let msg = ServerMessage::Find {
            prefix,
            client_blinded_identifier,
            zksm_proof,
            response: send,
        };
        
        self.sender.send(msg).await.expect("Actor task has been killed");
        recv.await.expect("Actor task has been killed")
    }

    /// Register a new user
    pub async fn register(&self, identifier: u64, uuid: Uuid) -> RegisterResponse {
        let (send, recv) = oneshot::channel();
        let msg = ServerMessage::Register {
            identifier,
            uuid,
            response: send,
        };
        
        self.sender.send(msg).await.expect("Actor task has been killed");
        recv.await.expect("Actor task has been killed")
    }
}

/// The ServerActor that manages the Server instance
pub struct ServerActor {
    server: Server,
    receiver: mpsc::Receiver<ServerMessage>,
}

impl ServerActor {
    /// Create a new ServerActor
    pub fn new(server: Server, receiver: mpsc::Receiver<ServerMessage>) -> Self {
        Self { server, receiver }
    }

    /// Create a new ServerActor with handle
    pub fn spawn(server: Server) -> ServerHandle {
        let (sender, receiver) = mpsc::channel(32);
        let actor = ServerActor::new(server, receiver);
        
        tokio::spawn(actor.run());
        ServerHandle::new(sender)
    }

    /// Main actor loop
    async fn run(mut self) {
        while let Some(msg) = self.receiver.recv().await {
            self.handle_message(msg).await;
        }
        info!("ServerActor shutting down");
    }

    /// Handle incoming messages
    async fn handle_message(&mut self, msg: ServerMessage) {
        match msg {
            ServerMessage::GetPublicSet { response } => {
                let result = self.server.get_public_set();
                let _ = response.send(result);
            }
            ServerMessage::Find {
                prefix,
                client_blinded_identifier,
                zksm_proof,
                response,
            } => {
                let mut rng = rand::thread_rng();
                
                let result = match (
                    EncodedPoint::from_bytes(&client_blinded_identifier),
                    serde_json::from_str::<ZKSMProof>(&zksm_proof),
                ) {
                    (Ok(client_blinded_point), Ok(zksm)) => {
                        let double_blinded_point = self.server.blind_identifier(&client_blinded_point);
                        
                        match self.server.find_bucket(prefix, &zksm, &mut rng) {
                            Some(bucket) => {
                                let entries = bucket
                                    .into_iter()
                                    .map(|(k, v)| (k.as_bytes().to_vec(), v.as_bytes().to_vec()))
                                    .collect();
                                Some((double_blinded_point.as_bytes().to_vec(), entries))
                            }
                            None => None,
                        }
                    }
                    _ => None,
                };
                
                let _ = response.send(result);
            }
            ServerMessage::Register {
                identifier,
                uuid,
                response,
            } => {
                let mut rng = rand::thread_rng();
                let result = self.server.register(identifier, &uuid, &mut rng);
                let _ = response.send(result);
            }
        }
    }
} 