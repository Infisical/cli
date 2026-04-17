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
use std::time::Instant;

use anyhow::{Context, Result};
use clap::Args;
use ironrdp_acceptor::{Acceptor, BeginResult};
use ironrdp_connector::{ClientConnector, DesktopSize};
use ironrdp_core::ReadCursor;
use ironrdp_pdu::Action;
use ironrdp_pdu::input::fast_path::{FastPathInput, FastPathInputEvent};
use ironrdp_pdu::nego::SecurityProtocol;
use ironrdp_pdu::rdp::client_info::Credentials as AcceptorCredentials;
use ironrdp_tokio::FramedWrite;
use ironrdp_tokio::reqwest::ReqwestNetworkClient;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

use crate::caps::{acceptor_capabilities, default_desktop_size};
use crate::config::connector_config;
use crate::events::{self, EventSender, SessionEvent, elapsed_ns_since};

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

/// Standalone-binary entry: loops forever, handling one connection at a
/// time, logging events to stdout via the debug logger.
pub async fn run(args: ProxyArgs) -> Result<()> {
    info!(listen = %args.listen, target = %args.target, "proxy-mode: starting");

    let listener = TcpListener::bind(args.listen)
        .await
        .with_context(|| format!("bind {}", args.listen))?;

    let server_tls = Arc::new(build_acceptor_tls().context("build acceptor TLS config")?);

    loop {
        let (client_tcp, peer) = listener.accept().await.context("accept")?;
        info!(%peer, "inbound connection");

        // For standalone mode we spin up a local logger per session.
        let (tx, rx) = events::channel();
        let logger = spawn_event_logger(rx);

        let server_tls = Arc::clone(&server_tls);
        if let Err(err) = handle_one(client_tcp, server_tls, args.clone(), tx).await {
            error!(?err, "session failed");
        }

        // Drain remaining events before the next connection.
        let _ = logger.await;
    }
}

/// FFI entry: accepts exactly one inbound connection, bridges it, and
/// pipes decoded events into the caller-provided channel. Returns when
/// the session ends.
pub async fn run_single_with_events(args: ProxyArgs, tx: EventSender) -> Result<()> {
    info!(listen = %args.listen, target = %args.target, "ffi bridge: starting");

    let listener = TcpListener::bind(args.listen)
        .await
        .with_context(|| format!("bind {}", args.listen))?;

    let server_tls = Arc::new(build_acceptor_tls().context("build acceptor TLS config")?);

    let (client_tcp, peer) = listener.accept().await.context("accept")?;
    info!(%peer, "ffi bridge: inbound connection");

    // Drop the listener so the port is freed immediately after the one
    // connection we accept.
    drop(listener);

    handle_one(client_tcp, server_tls, args, tx).await
}

/// FFI entry used by the Go gateway: consumes an already-accepted TCP
/// stream (handed over as a file descriptor) instead of listening. The
/// target-side handshake still happens normally.
pub async fn run_with_stream(
    client_tcp: TcpStream,
    target: String,
    username: String,
    password: String,
    tx: EventSender,
) -> Result<()> {
    info!(%target, "ffi bridge: starting with pre-accepted stream");

    let server_tls = Arc::new(build_acceptor_tls().context("build acceptor TLS config")?);

    // Build a ProxyArgs-equivalent for the target side. `listen` is unused
    // in this path but the shared `handle_one` takes it.
    let args = ProxyArgs {
        listen: "0.0.0.0:0".parse().expect("placeholder"),
        target,
        username,
        password,
    };

    handle_one(client_tcp, server_tls, args, tx).await
}

fn spawn_event_logger(mut rx: events::EventReceiver) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            match &event {
                SessionEvent::KeyboardInput {
                    scancode,
                    flags,
                    elapsed_ns,
                } => debug!(?flags, scancode, elapsed_ns, "KeyboardInput"),
                SessionEvent::UnicodeInput {
                    code_point,
                    flags,
                    elapsed_ns,
                } => debug!(?flags, code_point, elapsed_ns, "UnicodeInput"),
                SessionEvent::MouseInput {
                    x,
                    y,
                    flags,
                    wheel_delta,
                    elapsed_ns,
                } => debug!(?flags, x, y, wheel_delta, elapsed_ns, "MouseInput"),
                SessionEvent::TargetFrame {
                    action,
                    bytes,
                    elapsed_ns,
                } => debug!(?action, bytes, elapsed_ns, "TargetFrame"),
            }
        }
    })
}

async fn handle_one(
    client_tcp: TcpStream,
    server_tls: Arc<tokio_rustls::rustls::ServerConfig>,
    args: ProxyArgs,
    tx: EventSender,
) -> Result<()> {
    // Auto-detect entry protocol by peeking at the first byte:
    //   * 0x03 = TPKT, raw RDP from a CLI client (existing flow below).
    //   * 0x30 = ASN.1 SEQUENCE, RDCleanPath from a browser client.
    // Everything else is rejected.
    let first = crate::rdcleanpath::peek_first_byte(&client_tcp)
        .await
        .context("peek first byte")?;
    if first == 0x30 {
        info!("handle_one: detected RDCleanPath (browser flow)");
        return crate::rdcleanpath::handle_browser_session(
            client_tcp,
            args.target
                .rsplit_once(':')
                .map(|(h, _)| h)
                .unwrap_or(&args.target),
            args.target
                .rsplit_once(':')
                .and_then(|(_, p)| p.parse().ok())
                .unwrap_or(3389),
            &args.username,
            &args.password,
        )
        .await;
    }
    if first != 0x03 {
        anyhow::bail!("unrecognized first byte: {:02x}", first);
    }

    // --- CLIENT-FACING: acceptor handshake (CLI flow) ---

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
    //
    // The event channel is provided by the caller. Standalone binary mode
    // wires it to a local logger; FFI mode wires it to the poll_event
    // queue drained by Go.
    bridge_pdus(acceptor_framed, upgraded_framed, tx).await?;
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
    tx: EventSender,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
    T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    let (mut client_read, mut client_write) = ironrdp_tokio::split_tokio_framed(client_framed);
    let (mut target_read, mut target_write) = ironrdp_tokio::split_tokio_framed(target_framed);

    let started_at = Instant::now();
    let tx_c2t = tx.clone();
    let tx_t2c = tx;

    // client -> target: input PDUs. Decode FastPath input for the event
    // tap, then forward the raw bytes unchanged.
    let c2t = async move {
        loop {
            let (action, frame) = match client_read.read_pdu().await {
                Ok(v) => v,
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err::<_, anyhow::Error>(e.into()),
            };
            tap_client_to_target(action, &frame, started_at, &tx_c2t);
            target_write
                .write_all(&frame)
                .await
                .context("write frame to target")?;
        }
        Ok(())
    };

    // target -> client: output PDUs. Emit a TargetFrame event with
    // metadata (no payload capture yet) and forward bytes.
    let t2c = async move {
        loop {
            let (action, frame) = match target_read.read_pdu().await {
                Ok(v) => v,
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err::<_, anyhow::Error>(e.into()),
            };
            tap_target_to_client(action, &frame, started_at, &tx_t2c);
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

fn tap_client_to_target(action: Action, frame: &[u8], started_at: Instant, tx: &EventSender) {
    // Only FastPath input carries keyboard/mouse events. X.224 input is
    // rare today; most clients use FastPath exclusively. Emit nothing for
    // X.224 input in this step; decode in a later pass if needed.
    if action != Action::FastPath {
        return;
    }

    let input: FastPathInput = match decode_fast_path_input(frame) {
        Ok(input) => input,
        Err(e) => {
            warn!(?e, "failed to decode FastPathInput");
            return;
        }
    };

    let elapsed_ns = elapsed_ns_since(started_at);

    for event in input.input_events() {
        let session_event = match *event {
            FastPathInputEvent::KeyboardEvent(flags, scancode) => SessionEvent::KeyboardInput {
                scancode,
                flags,
                elapsed_ns,
            },
            FastPathInputEvent::UnicodeKeyboardEvent(flags, code_point) => {
                SessionEvent::UnicodeInput {
                    code_point,
                    flags,
                    elapsed_ns,
                }
            }
            FastPathInputEvent::MouseEvent(pdu) => SessionEvent::MouseInput {
                x: pdu.x_position,
                y: pdu.y_position,
                flags: pdu.flags,
                wheel_delta: pdu.number_of_wheel_rotation_units,
                elapsed_ns,
            },
            // MouseEventEx, MouseEventRel, QoeEvent, SyncEvent: not
            // decoded yet. Uncommon for basic sessions; add variants in a
            // later pass if we see them in practice.
            _ => continue,
        };
        // Drop on send-error means the receiver went away; that's fine,
        // means the session is shutting down.
        let _ = tx.send(session_event);
    }
}

fn tap_target_to_client(action: Action, frame: &[u8], started_at: Instant, tx: &EventSender) {
    let _ = tx.send(SessionEvent::TargetFrame {
        action,
        bytes: frame.len(),
        elapsed_ns: elapsed_ns_since(started_at),
    });
}

fn decode_fast_path_input(frame: &[u8]) -> anyhow::Result<FastPathInput> {
    let mut cursor = ReadCursor::new(frame);
    use ironrdp_core::Decode as _;
    FastPathInput::decode(&mut cursor).map_err(|e| anyhow::anyhow!("decode FastPathInput: {e}"))
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
