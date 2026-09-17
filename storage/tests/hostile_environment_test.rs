use koknet_core::crypto::{decrypt_payload, encrypt_payload, SecureSession};
use koknet_core::identity::NodeIdentity;
use std::fs;
use storage::crdt::CrdtRecord;
use storage::db::KoknetDb;

#[test]
fn test_hostile_environment_and_crdt_resolution() {
    // 1. Setup: Node Identities
    let alice = NodeIdentity::generate();
    let _bob = NodeIdentity::generate(); // Unused variable warning fixed with '_'
    let eve = NodeIdentity::generate(); // The Attacker

    // 2. Setup: E2EE Session between Alice and Bob
    let alice_session = SecureSession::new();
    let bob_session = SecureSession::new();

    // Save public keys before consumption to respect Rust ownership rules
    let alice_pub = alice_session.public_key();
    let bob_pub = bob_session.public_key();

    let alice_shared_secret = alice_session.derive_shared_secret(&bob_pub);
    let bob_shared_secret = bob_session.derive_shared_secret(&alice_pub);

    // 3. Setup: Local Databases for Alice and Bob
    let alice_db_path = "alice_test_db.sqlite";
    let bob_db_path = "bob_test_db.sqlite";
    let _ = fs::remove_file(alice_db_path); // Clean previous test runs
    let _ = fs::remove_file(bob_db_path);

    let alice_db = KoknetDb::new(alice_db_path).expect("Alice DB failed");
    let bob_db = KoknetDb::new(bob_db_path).expect("Bob DB failed");

    // =====================================================================
    // SCENARIO 1: Alice creates V1 of a record
    // =====================================================================
    let record_id = "mission_critical_doc".to_string();
    let payload_v1 = b"Location: Safehouse A";

    let encrypted_v1 = encrypt_payload(&alice_shared_secret, payload_v1).unwrap();
    let sig_v1 = alice.sign(&encrypted_v1).to_bytes().to_vec();

    let mut crdt_v1 = CrdtRecord::new(
        record_id.clone(),
        hex::encode(alice.public_key().as_bytes()),
        encrypted_v1,
        sig_v1,
    );
    // Force a specific older timestamp for testing
    crdt_v1.timestamp = 1000;

    alice_db.merge_crdt_record(&crdt_v1).unwrap();

    // =====================================================================
    // SCENARIO 2: Alice creates V2 of the same record (Update)
    // =====================================================================
    let payload_v2 = b"Location Compromised! Move to Safehouse B";
    let encrypted_v2 = encrypt_payload(&alice_shared_secret, payload_v2).unwrap();
    let sig_v2 = alice.sign(&encrypted_v2).to_bytes().to_vec();

    let mut crdt_v2 = CrdtRecord::new(
        record_id.clone(),
        hex::encode(alice.public_key().as_bytes()),
        encrypted_v2,
        sig_v2,
    );
    // Newer timestamp
    crdt_v2.timestamp = 2000;

    alice_db.merge_crdt_record(&crdt_v2).unwrap(); // Alice updates her local state

    // =====================================================================
    // SCENARIO 3: The Attacker (Eve) tries to manipulate the network
    // =====================================================================

    // Attack A: Eve intercepts V2 and tampers with the ciphertext (e.g. flipping bits)
    let mut tampered_v2 = crdt_v2.clone();
    tampered_v2.payload[15] ^= 0x01; // Flip a bit in the encrypted payload

    let decryption_attempt = decrypt_payload(&bob_shared_secret, &tampered_v2.payload);
    assert!(
        decryption_attempt.is_err(),
        "FATAL: Bob successfully decrypted tampered data! MAC verification failed."
    );

    // Attack B: Eve creates a fake record claiming to be Alice, signs it with Eve's key
    let fake_payload = b"Surrender to the enemy";
    let fake_encrypted = encrypt_payload(&alice_shared_secret, fake_payload).unwrap(); // Assuming Eve somehow got the session key (worst case)
    let fake_sig = eve.sign(&fake_encrypted).to_bytes().to_vec(); // Signed by EVE

    // Bob verifies the signature against ALICE's public key (the claimed author)
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let claimed_pub_key =
        VerifyingKey::from_bytes(&hex::decode(&crdt_v1.author_id).unwrap().try_into().unwrap())
            .unwrap();
    let parsed_fake_sig = Signature::from_bytes(&fake_sig.try_into().unwrap());

    let verification = claimed_pub_key.verify(&fake_encrypted, &parsed_fake_sig);
    assert!(
        verification.is_err(),
        "FATAL: Eve successfully impersonated Alice! Signature verification failed."
    );

    // =====================================================================
    // SCENARIO 4: Out-of-Order Delivery & CRDT LWW Resolution
    // =====================================================================

    // Bob receives V2 (the newer record) FIRST due to P2P network routing
    let merged_v2 = bob_db.merge_crdt_record(&crdt_v2).unwrap();
    assert!(merged_v2, "Bob should accept the new V2 record.");

    // Bob later receives V1 (the older record) because a slow node finally synced
    let merged_v1 = bob_db.merge_crdt_record(&crdt_v1).unwrap();
    assert!(
        !merged_v1,
        "Bob MUST reject V1 because he already has a newer timestamp for this ID."
    );

    // Verify Bob's final state matches Alice's V2 payload
    let bob_records = bob_db.get_all_records().unwrap();
    assert_eq!(bob_records.len(), 1);
    assert_eq!(bob_records[0].timestamp, 2000);

    let final_decrypted = decrypt_payload(&bob_shared_secret, &bob_records[0].payload).unwrap();
    assert_eq!(
        final_decrypted,
        b"Location Compromised! Move to Safehouse B"
    );

    // Cleanup
    let _ = fs::remove_file(alice_db_path);
    let _ = fs::remove_file(bob_db_path);
}
