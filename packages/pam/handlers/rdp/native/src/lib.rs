//! Infisical RDP bridge library.
//!
//! Exposes:
//! - A native Rust API in `bridge` for in-process consumers (used by the
//!   spike binary and tests).
//! - A handle-based C ABI in `ffi` for Go consumers via CGo.
//!
//! See README.md for Phase 0 / Phase 1 scope.

pub mod bridge;
pub mod caps;
pub mod client;
pub mod config;
pub mod events;
pub mod ffi;
