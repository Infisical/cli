//! Infisical RDP MITM bridge. Accepts inbound RDP with a placeholder
//! credential, connects outbound with gateway-injected credentials, then
//! passes bytes through.

pub mod bridge;
pub mod config;
pub mod ffi;
