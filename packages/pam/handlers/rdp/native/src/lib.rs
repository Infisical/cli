//! Infisical RDP MITM bridge. Accepts inbound RDP with a placeholder
//! credential, connects outbound with gateway-injected credentials, then
//! passes bytes through.

pub mod bridge;
pub mod cap_filter;
pub mod config;
pub mod events;
pub mod ffi;
pub mod rdcleanpath;
