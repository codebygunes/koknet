use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

/// Handles Diffie-Hellman key exchange to establish secure, End-to-End Encrypted (E2EE)
/// communication sessions between peers, ensuring perfect forward secrecy.
pub struct SecureSession {
    secret: EphemeralSecret,
}

impl SecureSession {
    pub fn new() -> Self {
        Self {
            secret: EphemeralSecret::random_from_rng(OsRng),
        }
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey::from(&self.secret)
    }

    /// Derives a shared secret using the local ephemeral secret and the remote peer's public key.
    pub fn derive_shared_secret(self, peer_public: &PublicKey) -> SharedSecret {
        self.secret.diffie_hellman(peer_public)
    }
}

/// Encrypts CRDT payloads or arbitrary messages using ChaCha20Poly1305 (AEAD).
/// Chosen for its high performance on mobile/edge devices and resistance to timing attacks.
pub fn encrypt_payload(shared_secret: &SharedSecret, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = ChaCha20Poly1305::new(shared_secret.as_bytes().into());

    // Generate a secure 12-byte random nonce for AEAD encryption
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let mut ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| "Encryption failed".to_string())?;

    // Prepend the nonce to the ciphertext (required for decryption)
    let mut result = nonce_bytes.to_vec();
    result.append(&mut ciphertext);

    Ok(result)
}

/// Decrypts incoming encrypted CRDT packets and verifies their integrity (MAC verification).
/// Prevents chosen-ciphertext attacks and ensures data hasn't been tampered with by middleboxes (e.g., DPI).
pub fn decrypt_payload(
    shared_secret: &SharedSecret,
    encrypted_data: &[u8],
) -> Result<Vec<u8>, String> {
    if encrypted_data.len() < 12 {
        return Err("Invalid data length: missing nonce".into());
    }

    let cipher = ChaCha20Poly1305::new(shared_secret.as_bytes().into());
    let nonce = Nonce::from_slice(&encrypted_data[0..12]);
    let ciphertext = &encrypted_data[12..];

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Decryption failed (MAC verification error - Payload may be tampered)".into())
}
