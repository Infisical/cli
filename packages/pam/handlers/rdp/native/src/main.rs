//! Phase 0 spike: IronRDP credential injection + MITM bridge.
//!
//! Two subcommands:
//!   * `client` -- connect to a Windows target using provided credentials,
//!                 drive the full RDP handshake (including CredSSP/NLA),
//!                 hold the session open briefly, disconnect. Proves that
//!                 credential injection via the connector works end-to-end.
//!   * `proxy`  -- accept an inbound RDP connection, terminate it, open a
//!                 new outbound connection to the target with credential
//!                 injection, bridge bytes. Full MITM. Structured skeleton;
//!                 parts marked TODO need integration testing.
//!
//! Deliberately minimal: no event tap, no FFI, no recording.
//! See README.md for the POC scope.

mod bridge;
mod caps;
mod client;
mod config;
mod events;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(about = "Infisical RDP bridge (Phase 0 spike)")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Connect directly to a Windows target as an RDP client.
    /// Proves that credential injection via CredSSP works.
    Client(client::ClientArgs),
    /// Full MITM proxy. Accepts an inbound RDP connection, injects
    /// credentials on the outbound half. Scaffolding -- needs integration
    /// testing against a real Windows target before it can be called working.
    Proxy(bridge::ProxyArgs),
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,ironrdp=info".into()),
        )
        .init();

    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install rustls crypto provider"))?;

    let cli = Cli::parse();

    match cli.command {
        Command::Client(args) => client::run(args).await,
        Command::Proxy(args) => bridge::run(args).await,
    }
}
