//! Infisical RDP MITM bridge.
//!
//! The bridge accepts an inbound RDP connection from a native client
//! (xfreerdp, mstsc) on one side and initiates an outbound RDP connection
//! to a Windows target on the other. The outbound handshake performs
//! CredSSP/NLA with credentials injected by the gateway, so the real
//! target credentials never reach the client. The inbound handshake
//! accepts a fixed placeholder credential (`infisical`/`infisical`) that
//! the CLI embeds in the generated .rdp file.
//!
//! Phase 1 scope: standalone test binary only, no FFI, no event tap.

pub mod bridge;
pub mod config;
