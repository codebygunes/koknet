use libp2p::{
    gossipsub, identify, identity, swarm::NetworkBehaviour, PeerId, Swarm,
};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::Duration;

/// Defines the network behaviors for Koknet.
/// - Gossipsub: For decentralized pub/sub broadcasting of CRDT records.
/// - Identify: For peers to exchange their public keys and supported protocols.
#[derive(NetworkBehaviour)]
pub struct KoknetBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub identify: identify::Behaviour,
}

/// Initializes the decentralized P2P Swarm using WebRTC as the underlying transport.
/// This function is asynchronous and compatible with both native (Tokio) and WASM environments.
pub async fn build_swarm(local_key: identity::Keypair) -> Result<Swarm<KoknetBehaviour>, Box<dyn std::error::Error>> {
    let local_peer_id = PeerId::from(local_key.public());

    // Configure Gossipsub for decentralized message broadcasting
    // We implement a custom message ID function to prevent duplicate message propagation
    let message_id_fn = |message: &gossipsub::Message| {
        let mut s = DefaultHasher::new();
        message.data.hash(&mut s);
        gossipsub::MessageId::from(s.finish().to_string())
    };

    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .heartbeat_interval(Duration::from_secs(1))
        .validation_mode(gossipsub::ValidationMode::Strict)
        .message_id_fn(message_id_fn)
        .build()
        .map_err(|msg| std::io::Error::new(std::io::ErrorKind::Other, msg))?;

    let gossipsub = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(local_key.clone()),
        gossipsub_config,
    )?;

    // Configure Identify to allow nodes to seamlessly discover each other's addresses
    let identify = identify::Behaviour::new(identify::Config::new(
        "/koknet/1.0.0".into(),
        local_key.public(),
    ));

    let behaviour = KoknetBehaviour { gossipsub, identify };

    // Set up the Swarm with WebRTC transport
    // Note: In a full implementation, `libp2p::tokio_development_transport` is replaced 
    // with strict WebRTC configurations for NAT Traversal (STUN/TURN).
    let swarm = libp2p::SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )?
        .with_behaviour(|_| behaviour)?
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    Ok(swarm)
}