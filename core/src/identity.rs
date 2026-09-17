use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;

/// Represents the immutable and cryptographically secure identity of a peer (node) in the Koknet network.
/// Designed for decentralized environments without relying on central Certificate Authorities (CAs).
pub struct NodeIdentity {
    signing_key: SigningKey,
}

impl NodeIdentity {
    /// Generates a new, secure Ed25519 identity using a cryptographically secure pseudorandom number generator (CSPRNG).
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        Self { signing_key }
    }

    /// Returns the public key used to identify the node across the decentralized network.
    /// Acts as the Node ID to maintain anonymity while allowing cryptographic verification.
    pub fn public_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Signs CRDT records or P2P messages to guarantee data integrity and author authenticity 
    /// against tampering in hostile network environments.
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    /// Verifies if an incoming message or CRDT payload was legitimately signed by the claimed peer.
    pub fn verify(public_key: &VerifyingKey, message: &[u8], signature: &Signature) -> bool {
        public_key.verify(message, signature).is_ok()
    }
}