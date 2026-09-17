use wasm_bindgen::prelude::*;
use libp2p::identity;
use crate::p2p::build_swarm;

/// Initializes the Koknet P2P node inside a web browser via WebAssembly.
/// This exposes a JavaScript-compatible asynchronous function.
#[wasm_bindgen]
pub async fn start_koknet_wasm_node() -> Result<JsValue, JsValue> {
    // Generate an ephemeral cryptographic identity for the browser session
    let local_key = identity::Keypair::generate_ed25519();
    let local_peer_id = libp2p::PeerId::from(local_key.public());

    // Initialize the WebRTC Swarm tailored for the browser
    match build_swarm(local_key).await {
        Ok(_) => {
            let success_msg = format!("Koknet WASM Node started successfully. PeerID: {}", local_peer_id);
            Ok(JsValue::from_str(&success_msg))
        },
        Err(e) => {
            let err_msg = format!("Failed to start Koknet WASM node: {}", e);
            Err(JsValue::from_str(&err_msg))
        }
    }
}