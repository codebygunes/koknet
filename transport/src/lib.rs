pub mod dpi_evasion;
pub mod p2p;

// Only compile the WASM bindings if the target architecture is WebAssembly
#[cfg(target_arch = "wasm32")]
pub mod wasm;
