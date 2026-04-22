//! Standalone test binary. Listens on a loopback port, accepts one
//! connection, runs the MITM bridge to a Windows target, and exits.
//!
//! Validate against a real Windows server with any native RDP client
//! using credentials `infisical`/`infisical`; see the crate README for
//! tested client commands.

use std::net::SocketAddr;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use infisical_rdp_bridge::bridge::{run_mitm, TargetEndpoint};

#[derive(Parser, Debug)]
#[command(about = "Infisical RDP MITM bridge: manual validation harness")]
struct Args {
    /// Loopback address to listen on for the native RDP client.
    #[arg(long, default_value = "127.0.0.1:3390")]
    listen: SocketAddr,

    /// Target Windows RDP server host.
    #[arg(long)]
    target_host: String,

    /// Target Windows RDP server port.
    #[arg(long, default_value_t = 3389)]
    target_port: u16,

    /// Username to inject on the outbound connection.
    #[arg(long)]
    username: String,

    /// Password to inject on the outbound connection.
    #[arg(long)]
    password: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    let listener = TcpListener::bind(args.listen)
        .await
        .with_context(|| format!("bind {}", args.listen))?;
    info!(
        listen = %args.listen,
        target = %format!("{}:{}", args.target_host, args.target_port),
        "bridge ready; waiting for one RDP client connection"
    );

    let (client_tcp, peer) = listener.accept().await.context("accept")?;
    info!(%peer, "inbound connection; starting MITM");
    drop(listener);

    let endpoint = TargetEndpoint {
        host: args.target_host,
        port: args.target_port,
        username: args.username,
        password: args.password,
    };

    // Test binary never cancels; pass a fresh token that stays uncancelled.
    let cancel = CancellationToken::new();
    match run_mitm(client_tcp, endpoint, cancel).await {
        Ok(()) => {
            info!("session ended cleanly");
            Ok(())
        }
        Err(e) => {
            error!(error = ?e, "session failed");
            Err(e)
        }
    }
}
