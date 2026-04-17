//! Phase 0a: standalone RDP client with credential injection.
//!
//! Opens an outbound RDP connection to a Windows target, injects the
//! provided credentials via CredSSP, completes the handshake, then
//! disconnects. Proves that the connector + CredSSP half of the bridge
//! works against a real Windows target.
//!
//! This intentionally does NOT enter the active-phase event loop. The goal
//! is to validate connection + authentication, not to render a session.

use anyhow::{Context, Result};
use clap::Args;
use ironrdp_connector::{self, ClientConnector};
use ironrdp_tokio::reqwest::ReqwestNetworkClient;
use tokio::net::TcpStream;
use tracing::info;

use crate::config::connector_config;

#[derive(Args, Debug)]
pub struct ClientArgs {
    /// Target Windows RDP server (host:port)
    #[arg(long)]
    pub target: String,

    /// Username to inject (local account; domain\\user for domain accounts)
    #[arg(long)]
    pub username: String,

    /// Password to inject
    #[arg(long)]
    pub password: String,
}

pub async fn run(args: ClientArgs) -> Result<()> {
    info!(target = %args.target, user = %args.username, "client-mode: connecting");

    let stream = TcpStream::connect(&args.target)
        .await
        .with_context(|| format!("tcp connect to {}", args.target))?;

    let client_addr = stream.local_addr().context("local_addr")?;
    let server_name = args
        .target
        .rsplit_once(':')
        .map(|(host, _)| host.to_owned())
        .unwrap_or_else(|| args.target.clone());

    let mut framed = ironrdp_tokio::TokioFramed::new(stream);

    let config = connector_config(args.username.clone(), args.password.clone(), 1920, 1080);
    let mut connector = ClientConnector::new(config, client_addr);

    // Drive the pre-TLS handshake (X.224 negotiation).
    let should_upgrade = ironrdp_tokio::connect_begin(&mut framed, &mut connector)
        .await
        .context("connect_begin")?;

    info!("TLS upgrade (target side)");

    // Upgrade to TLS. `ironrdp-tls::upgrade` accepts any cert (DangerousConfig).
    // For production the verifier needs to be driven by resource policy.
    let (initial_stream, leftover) = framed.into_inner();
    let (upgraded_stream, tls_cert) = ironrdp_tls::upgrade(initial_stream, &server_name)
        .await
        .context("tls upgrade")?;

    let upgraded = ironrdp_tokio::mark_as_upgraded(should_upgrade, &mut connector);

    let erased: Box<dyn AsyncReadWrite + Unpin + Send + Sync> = Box::new(upgraded_stream);
    let mut upgraded_framed = ironrdp_tokio::TokioFramed::new_with_leftover(erased, leftover);

    let server_public_key = ironrdp_tls::extract_tls_server_public_key(&tls_cert)
        .ok_or_else(|| anyhow::anyhow!("could not extract target's TLS public key"))?;

    // Complete the connection: CredSSP (with injected credentials) runs
    // inside connect_finalize, along with MCS, licensing, capability
    // exchange, and activation.
    let connection_result = ironrdp_tokio::connect_finalize(
        upgraded,
        connector,
        &mut upgraded_framed,
        &mut ReqwestNetworkClient::new(),
        ironrdp_connector::ServerName::new(&server_name),
        server_public_key.to_owned(),
        None, // KerberosConfig: None = NTLM-only, fine for local accounts
    )
    .await
    .context("connect_finalize (CredSSP + handshake)")?;

    info!(
        width = connection_result.desktop_size.width,
        height = connection_result.desktop_size.height,
        "RDP connection established -- credential injection succeeded"
    );

    // Phase 0 exit gate: if we got here, CredSSP accepted the credentials
    // and the Windows target opened a session. We're done for Phase 0a;
    // Phase 0b adds the acceptor side.
    info!("closing connection (Phase 0a doesn't run an active session)");

    Ok(())
}

trait AsyncReadWrite: tokio::io::AsyncRead + tokio::io::AsyncWrite {}
impl<T> AsyncReadWrite for T where T: tokio::io::AsyncRead + tokio::io::AsyncWrite {}
