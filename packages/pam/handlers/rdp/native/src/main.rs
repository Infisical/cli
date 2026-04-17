//! Thin binary wrapper. Real implementation lives in the library.
//!
//! Two subcommands for manual spike testing:
//!   * `client` -- connect to a Windows target using provided credentials.
//!                 Validates CredSSP injection end-to-end.
//!   * `proxy`  -- full MITM. Accepts an inbound RDP connection, injects
//!                 credentials on the outbound half, forwards PDUs.

use anyhow::Result;
use clap::{Parser, Subcommand};

use infisical_rdp_bridge::{bridge, client};

#[derive(Parser, Debug)]
#[command(about = "Infisical RDP bridge (Phase 0/1 spike)")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Client(client::ClientArgs),
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
