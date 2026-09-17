use serde::{Deserialize, Serialize};

/// The fundamental Data Model for the network, based on the LWW (Last-Write-Wins) CRDT architecture.
/// All data traveling through the decentralized network is encapsulated in this metadata-resistant format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrdtRecord {
    /// Unique identifier of the data record (e.g., "message_123" or "config_theme").
    pub id: String,
    /// The public key (Identity) of the Node that authored this record.
    pub author_id: String,
    /// Logical or physical timestamp used for LWW (Last-Write-Wins) conflict resolution.
    pub timestamp: i64,
    /// The actual data content (payload), which should be encrypted via `koknet_core` prior to network transit.
    pub payload: Vec<u8>,
    /// Ed25519 signature ensuring the record's integrity and non-repudiation.
    pub signature: Vec<u8>, 
}

impl CrdtRecord {
    pub fn new(id: String, author_id: String, payload: Vec<u8>, signature: Vec<u8>) -> Self {
        Self {
            id,
            author_id,
            timestamp: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
            payload,
            signature,
        }
    }
}