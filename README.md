# Köknet (KokSync)

> Zero-Metadata, Local-First, and DPI-Evading P2P Sync & Communication Core written in Rust.

## Architecture
- **core**: Cryptographic primitives, identity management, and state machine.
- **transport**: WebRTC / libp2p based decentralized tunneling & pluggable transport.
- **storage**: SQLite backed local-first engine with CRDT conflict-free synchronization.
- **cli**: Command-line interface for testing, node management, and debugging.

## License
MIT / Apache-2.0
