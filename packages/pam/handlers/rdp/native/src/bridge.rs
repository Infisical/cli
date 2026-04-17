//! Phase 1 Step 1: decoded-PDU forwarding with event tap.
//!
//! Differences from Phase 0:
//! - Acceptor advertises a real capability set (see caps.rs) so the inbound
//!   handshake negotiates a format the target will also use. No more
//!   capability mismatch.
//! - Post-handshake, we read one PDU at a time from each side using
//!   `read_pdu`. Each PDU is classified (X224 / FastPath) and its length
//!   logged through the event tap before the raw bytes are forwarded.
//! - The event tap is currently a logger; Step 2 wires it into a real
//!   event stream exposed across FFI.

use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Args;
use ironrdp_acceptor::{Acceptor, BeginResult};
use ironrdp_connector::{ClientConnector, DesktopSize};
use ironrdp_pdu::Action;
use ironrdp_pdu::nego::SecurityProtocol;
use ironrdp_pdu::rdp::client_info::Credentials as AcceptorCredentials;
use ironrdp_tokio::FramedWrite;
use ironrdp_tokio::reqwest::ReqwestNetworkClient;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, trace};

use crate::caps::{acceptor_capabilities, default_desktop_size};
use crate::config::connector_config;

#[derive(Args, Debug, Clone)]
pub struct ProxyArgs {
    /// Address to listen on for inbound RDP connections
    #[arg(long, default_value = "127.0.0.1:3389")]
    pub listen: std::net::SocketAddr,

    /// Target Windows RDP server (host:port) to proxy to
    #[arg(long)]
    pub target: String,

    /// Username to inject on the outbound connection
    #[arg(long)]
    pub username: String,

    /// Password to inject on the outbound connection
    #[arg(long)]
    pub password: String,
}

type ErasedStream = Box<dyn AsyncReadWrite + Send + Sync + Unpin + 'static>;

pub async fn run(args: ProxyArgs) -> Result<()> {
    info!(listen = %args.listen, target = %args.target, "proxy-mode: starting");

    let listener = TcpListener::bind(args.listen)
        .await
        .with_context(|| format!("bind {}", args.listen))?;

    let server_tls = Arc::new(build_acceptor_tls().context("build acceptor TLS config")?);

    loop {
        let (client_tcp, peer) = listener.accept().await.context("accept")?;
        info!(%peer, "inbound connection");

        let server_tls = Arc::clone(&server_tls);
        if let Err(err) = handle_one(client_tcp, server_tls, args.clone()).await {
            error!(?err, "session failed");
        }
    }
}

async fn handle_one(
    client_tcp: TcpStream,
    server_tls: Arc<tokio_rustls::rustls::ServerConfig>,
    args: ProxyArgs,
) -> Result<()> {
    // --- CLIENT-FACING: acceptor handshake ---

    let acceptor_framed = ironrdp_tokio::TokioFramed::new(client_tcp);
    let (width, height) = default_desktop_size();
    let capabilities = acceptor_capabilities(width, height);

    // Placeholder creds: RDP's TLS-only mode requires the client to send
    // username/password in the ClientInfoPdu. IronRDP's acceptor validates
    // these match what we pass here. Real architecture: the browser knows to
    // send a fixed placeholder; actual auth lives at the WebSocket layer.
    let placeholder_creds = AcceptorCredentials {
        username: "test".to_owned(),
        password: "test".to_owned(),
        domain: None,
    };
    let mut acceptor = Acceptor::new(
        SecurityProtocol::SSL,
        DesktopSize { width, height },
        capabilities,
        Some(placeholder_creds),
    );

    let begin_result = ironrdp_acceptor::accept_begin(acceptor_framed, &mut acceptor)
        .await
        .context("accept_begin")?;

    let acceptor_framed: ironrdp_tokio::TokioFramed<ErasedStream> = match begin_result {
        BeginResult::Continue(framed) => {
            let (stream, leftover) = framed.into_inner();
            let erased: ErasedStream = Box::new(stream);
            ironrdp_tokio::TokioFramed::new_with_leftover(erased, leftover)
        }
        BeginResult::ShouldUpgrade(tcp) => {
            info!("TLS upgrade (client side)");
            let tls_stream = tokio_rustls::TlsAcceptor::from(server_tls)
                .accept(tcp)
                .await
                .context("accept TLS from client")?;
            acceptor.mark_security_upgrade_as_done();
            let erased: ErasedStream = Box::new(tls_stream);
            ironrdp_tokio::TokioFramed::new(erased)
        }
    };

    if acceptor.should_perform_credssp() {
        anyhow::bail!("unexpected: client-side negotiated NLA despite SSL-only advertisement");
    }

    let (acceptor_framed, acceptor_result) =
        ironrdp_acceptor::accept_finalize(acceptor_framed, &mut acceptor)
            .await
            .context("accept_finalize")?;

    info!(
        user_channel_id = acceptor_result.user_channel_id,
        io_channel_id = acceptor_result.io_channel_id,
        "client-side handshake complete"
    );

    // --- TARGET-FACING: connector + CredSSP ---

    let target_tcp = TcpStream::connect(&args.target)
        .await
        .with_context(|| format!("tcp connect to {}", args.target))?;
    let client_addr = target_tcp.local_addr().context("local_addr")?;
    let server_name = args
        .target
        .rsplit_once(':')
        .map(|(host, _)| host.to_owned())
        .unwrap_or_else(|| args.target.clone());

    let mut target_framed = ironrdp_tokio::TokioFramed::new(target_tcp);
    let config = connector_config(args.username.clone(), args.password.clone(), width, height);
    let mut connector = ClientConnector::new(config, client_addr);

    let should_upgrade = ironrdp_tokio::connect_begin(&mut target_framed, &mut connector)
        .await
        .context("target connect_begin")?;

    let (initial_stream, leftover) = target_framed.into_inner();
    let (upgraded_stream, tls_cert) = ironrdp_tls::upgrade(initial_stream, &server_name)
        .await
        .context("target tls upgrade")?;

    let upgraded = ironrdp_tokio::mark_as_upgraded(should_upgrade, &mut connector);
    let erased: ErasedStream = Box::new(upgraded_stream);
    let mut upgraded_framed = ironrdp_tokio::TokioFramed::new_with_leftover(erased, leftover);

    let server_public_key = ironrdp_tls::extract_tls_server_public_key(&tls_cert)
        .ok_or_else(|| anyhow::anyhow!("target TLS public key extraction"))?;

    let connection_result = ironrdp_tokio::connect_finalize(
        upgraded,
        connector,
        &mut upgraded_framed,
        &mut ReqwestNetworkClient::new(),
        ironrdp_connector::ServerName::new(&server_name),
        server_public_key.to_owned(),
        None,
    )
    .await
    .context("target connect_finalize (CredSSP)")?;

    info!(
        target_width = connection_result.desktop_size.width,
        target_height = connection_result.desktop_size.height,
        "target-side handshake complete -- credential injection succeeded"
    );

    // --- BRIDGE: PDU-aware forwarding with event tap ---

    bridge_pdus(acceptor_framed, upgraded_framed).await?;

    Ok(())
}

/// Forward PDUs between client and target, tapping each for the event log.
///
/// Each side's read loop:
///   1. `read_pdu` yields `(Action, raw_bytes)` for one full PDU.
///   2. The event tap logs the action + length (Step 1: log only; Step 2
///      decodes payloads into structured events).
///   3. The raw bytes are written to the other side unchanged.
///
/// Because both handshakes agreed on compatible capabilities (see caps.rs),
/// the raw bytes are valid on the other side without re-encoding.
async fn bridge_pdus<C, T>(
    client_framed: ironrdp_tokio::TokioFramed<C>,
    target_framed: ironrdp_tokio::TokioFramed<T>,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
    T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    let (mut client_read, mut client_write) = ironrdp_tokio::split_tokio_framed(client_framed);
    let (mut target_read, mut target_write) = ironrdp_tokio::split_tokio_framed(target_framed);

    // client -> target: input PDUs (keyboard, mouse, channel data)
    let c2t = async move {
        loop {
            let (action, frame) = match client_read.read_pdu().await {
                Ok(v) => v,
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err::<_, anyhow::Error>(e.into()),
            };
            tap_client_to_target(action, &frame);
            target_write
                .write_all(&frame)
                .await
                .context("write frame to target")?;
        }
        Ok(())
    };

    // target -> client: output PDUs (bitmap updates, channel data)
    let t2c = async move {
        loop {
            let (action, frame) = match target_read.read_pdu().await {
                Ok(v) => v,
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err::<_, anyhow::Error>(e.into()),
            };
            tap_target_to_client(action, &frame);
            client_write
                .write_all(&frame)
                .await
                .context("write frame to client")?;
        }
        Ok(())
    };

    tokio::try_join!(c2t, t2c).context("bridge_pdus")?;
    Ok(())
}

/// Event tap -- client-to-target direction (input events).
///
/// Step 1: log action + length.
/// Step 2: decode FastPath input PDUs into KeyboardInput/MouseInput events
/// and push them onto an event channel exposed through FFI.
fn tap_client_to_target(action: Action, frame: &[u8]) {
    trace!(?action, len = frame.len(), "c->t");
}

/// Event tap -- target-to-client direction (output events).
///
/// Step 1: log action + length.
/// Step 2: decode FastPath graphics updates into BitmapRegion events (with
/// compressed payload forwarded as-is for lossless recording).
fn tap_target_to_client(action: Action, frame: &[u8]) {
    trace!(?action, len = frame.len(), "t->c");
}

fn build_acceptor_tls() -> Result<tokio_rustls::rustls::ServerConfig> {
    let subject_alt_names = vec!["localhost".to_string(), "infisical-rdp-bridge".to_string()];
    let cert = rcgen::generate_simple_self_signed(subject_alt_names)
        .context("generate self-signed cert")?;

    let cert_der = cert.cert.der().clone();
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());

    let config = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .context("build ServerConfig")?;

    Ok(config)
}

trait AsyncReadWrite: AsyncRead + AsyncWrite {}
impl<T> AsyncReadWrite for T where T: AsyncRead + AsyncWrite {}
