use transport::dpi_evasion::DpiObfuscator;
use std::collections::HashSet;

#[test]
fn test_traffic_analysis_resistance_via_padding() {
    // SCENARIO 1: Traffic Analysis & Packet Fingerprinting
    // A hostile ISP (e.g., Great Firewall) monitors packet sizes. If a specific 
    // encrypted payload always produces the exact same packet size, they can fingerprint it.
    // We must prove that encrypting the EXACT same payload 100 times produces highly randomized lengths.

    let secret_payload = b"Target coordinates: 45.12, 34.56";
    let mut observed_packet_sizes = HashSet::new();

    for _ in 0..100 {
        let masked_packet = DpiObfuscator::mask_payload(secret_payload);
        
        // Ensure the fake TLS 1.3 header is perfectly intact
        assert_eq!(&masked_packet[0..3], &[0x17, 0x03, 0x03], "Missing TLS 1.3 Header!");
        
        // Track the total packet size
        observed_packet_sizes.insert(masked_packet.len());
        
        // Verify that even with random padding, we can perfectly recover the data
        let unmasked = DpiObfuscator::unmask_payload(&masked_packet, secret_payload.len()).unwrap();
        assert_eq!(secret_payload, unmasked.as_slice(), "Data corrupted during unmasking!");
    }

    // Out of 100 encryptions, the padding randomness MUST produce varying packet sizes.
    // If it only produced 1 or 2 sizes, our traffic analysis resistance is broken.
    assert!(
        observed_packet_sizes.len() > 50,
        "FATAL: Padding is not random enough! Vulnerable to packet size fingerprinting."
    );
}

#[test]
fn test_active_dpi_probing_and_tampering() {
    // SCENARIO 2: Active DPI Probing
    // The firewall attempts to modify the fake TLS header or the payload length 
    // to force our parser to crash or execute an Out-Of-Bounds (OOB) memory read.

    let payload = b"Journalist source data";
    let masked_packet = DpiObfuscator::mask_payload(payload);

    // Attack A: Modify the TLS Header (e.g., change 0x17 to 0x16 - Handshake)
    let mut tampered_header = masked_packet.clone();
    tampered_header[0] = 0x16; 
    
    let result_a = DpiObfuscator::unmask_payload(&tampered_header, payload.len());
    assert!(
        result_a.is_err(),
        "FATAL: Parser accepted a manipulated TLS header!"
    );

    // Attack B: Length Spoofing (Buffer Overflow attempt)
    // The attacker claims the payload is 10,000 bytes, but the actual packet is small.
    // A naive parser would attempt to read 10,000 bytes and cause a panic (Denial of Service).
    let result_b = DpiObfuscator::unmask_payload(&masked_packet, 10_000);
    assert!(
        result_b.is_err(),
        "FATAL: Parser is vulnerable to Out-Of-Bounds read! DOS attack successful."
    );
}

#[test]
fn test_network_fragmentation_and_truncation() {
    // SCENARIO 3: TCP Fragmentation / Packet Drop
    // Due to poor network conditions or malicious firewall dropping, 
    // the packet is cut off halfway through.

    let payload = vec![0x42; 500]; // 500 bytes of dummy encrypted data
    let masked_packet = DpiObfuscator::mask_payload(&payload);

    // Attack C: Packet severely truncated (Only header arrives)
    let truncated_severe = &masked_packet[0..4]; 
    let result_c = DpiObfuscator::unmask_payload(truncated_severe, payload.len());
    assert!(
        result_c.is_err(),
        "FATAL: Parser tried to process a packet smaller than the minimum header size!"
    );

    // Attack D: Payload truncated (Missing the random padding and end of payload)
    // We cut the packet precisely before the payload ends.
    let truncated_payload = &masked_packet[0..300]; 
    let result_d = DpiObfuscator::unmask_payload(truncated_payload, payload.len());
    assert!(
        result_d.is_err(),
        "FATAL: Parser attempted to read payload bytes that do not exist!"
    );
}