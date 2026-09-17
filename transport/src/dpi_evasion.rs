use rand::Rng;

/// DPI Evasion Module (Censorship Obfuscation)
///
/// Restrictive firewalls often use Deep Packet Inspection (DPI) to block unknown P2P protocols.
/// This module masks Koknet's encrypted traffic by framing it exactly like standard
/// TLS 1.3 Application Data (HTTPS). To an external observer or firewall,
/// the stream is indistinguishable from standard web browsing.

const TLS_1_3_APPLICATION_DATA: [u8; 3] = [0x17, 0x03, 0x03]; // ContentType: Application Data, Legacy Version: TLS 1.2

pub struct DpiObfuscator;

impl DpiObfuscator {
    /// Wraps the encrypted CRDT payload in a fake TLS 1.3 record.
    /// It also appends randomized padding to defeat traffic analysis and packet size fingerprinting.
    pub fn mask_payload(encrypted_payload: &[u8]) -> Vec<u8> {
        let mut rng = rand::thread_rng();

        // Add random padding (between 16 and 128 bytes) to obscure the true data length
        let padding_len = rng.gen_range(16..=128);
        let mut padding = vec![0u8; padding_len];
        rng.fill(&mut padding[..]);

        // Total length of payload + padding
        let total_len = (encrypted_payload.len() + padding_len) as u16;
        let len_bytes = total_len.to_be_bytes();

        let mut disguised_packet = Vec::with_capacity(5 + encrypted_payload.len() + padding_len);

        // Write the fake TLS header
        disguised_packet.extend_from_slice(&TLS_1_3_APPLICATION_DATA);
        disguised_packet.extend_from_slice(&len_bytes);

        // Write the actual encrypted payload
        disguised_packet.extend_from_slice(encrypted_payload);

        // Write the random padding
        disguised_packet.extend_from_slice(&padding);

        disguised_packet
    }

    /// Strips the fake TLS 1.3 header and padding to recover the original encrypted CRDT payload.
    /// Returns an Error if the packet structure is invalid.
    pub fn unmask_payload(
        disguised_packet: &[u8],
        actual_payload_len: usize,
    ) -> Result<Vec<u8>, &'static str> {
        if disguised_packet.len() < 5 {
            return Err("Packet too short to contain a valid DPI-evasion header");
        }

        // Verify the fake TLS header matches
        if &disguised_packet[0..3] != TLS_1_3_APPLICATION_DATA {
            return Err("Invalid DPI-evasion header: Not TLS 1.3 format");
        }

        // Extract the original encrypted payload (ignoring the padding at the end)
        let payload_start = 5;
        let payload_end = payload_start + actual_payload_len;

        if payload_end > disguised_packet.len() {
            return Err("Packet length mismatch during unmasking");
        }

        Ok(disguised_packet[payload_start..payload_end].to_vec())
    }
}
