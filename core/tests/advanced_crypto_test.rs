use koknet_core::crypto::{decrypt_payload, encrypt_payload, SecureSession};

#[test]
fn test_nonce_uniqueness_and_replay_resistance() {
    let alice = SecureSession::new();
    let bob = SecureSession::new();
    let shared_secret = alice.derive_shared_secret(&bob.public_key());

    let message = b"Critical command: Execute sync";

    // Encrypting the same message twice with the same session key
    let cipher1 = encrypt_payload(&shared_secret, message).expect("Encryption 1 failed");
    let cipher2 = encrypt_payload(&shared_secret, message).expect("Encryption 2 failed");

    // RULE 1: Nonce values (the first 12 bytes) must be strictly different!
    assert_ne!(
        &cipher1[0..12],
        &cipher2[0..12],
        "FATAL: Nonce reuse detected! This breaks ChaCha20Poly1305 security."
    );

    // RULE 2: The entire ciphertexts must be completely different from each other.
    assert_ne!(
        cipher1, cipher2,
        "Ciphertexts must be different for identical payloads due to nonce randomness."
    );
}

#[test]
fn test_perfect_forward_secrecy_isolation() {
    // 1. Session (Old)
    let alice_session_1 = SecureSession::new();
    let bob_session_1 = SecureSession::new();
    let secret_1 = alice_session_1.derive_shared_secret(&bob_session_1.public_key());

    let message = b"Compromised session data";
    let cipher_1 = encrypt_payload(&secret_1, message).unwrap();

    // 2. Session (Keys rotated - New)
    let alice_session_2 = SecureSession::new();
    let bob_session_2 = SecureSession::new();
    let bob_secret_2 = bob_session_2.derive_shared_secret(&alice_session_2.public_key());

    // Bob accidentally or maliciously tries to decrypt a packet from the old session
    // using the newly rotated session key.
    let attempt = decrypt_payload(&bob_secret_2, &cipher_1);
    
    assert!(
        attempt.is_err(),
        "PFS Breach: Old messages must NOT be readable with new session keys!"
    );
}

#[test]
fn test_empty_and_large_payload_handling() {
    let alice = SecureSession::new();
    let bob = SecureSession::new();
    let shared_secret = alice.derive_shared_secret(&bob.public_key());

    // Scenario A: Empty Payload (e.g., P2P Heartbeat / Ping message)
    let empty_payload: &[u8] = b"";
    let encrypted_empty = encrypt_payload(&shared_secret, empty_payload).unwrap();
    let decrypted_empty = decrypt_payload(&shared_secret, &encrypted_empty).unwrap();
    assert_eq!(empty_payload, decrypted_empty.as_slice());

    // Scenario B: Large Payload (e.g., 5MB file transfer)
    // Pushes Rust's memory allocation limits to test memory safety and prevent leaks.
    let large_payload = vec![0x42; 5 * 1024 * 1024]; // 5 MB dummy data
    let encrypted_large = encrypt_payload(&shared_secret, &large_payload).unwrap();
    let decrypted_large = decrypt_payload(&shared_secret, &encrypted_large).unwrap();
    assert_eq!(large_payload, decrypted_large);
}