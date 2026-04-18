//! RDCleanPath browser-flow handler for the gateway.
//!
//! Splits the pipeline into two halves so we can MITM-inject credentials
//! while still using IronRDP's web client unchanged:
//!
//!   Browser  <--WS-->  [gateway SSL-only TLS]  <--MITM-->  [gateway HYBRID_EX + CredSSP]  <--TCP/TLS-->  Target
//!
//! We downgrade the *browser's* view to SSL-only by fabricating the
//! X.224 CC we put in the RDCleanPath Response. The browser then does
//! plain RDP-over-TLS, so we never have to run a server-side CredSSP.
//! The target side keeps HYBRID_EX and CredSSP, which is where the real
//! credential injection happens.
//!
//! The browser validates our self-signed cert against whatever chain we
//! include in the RDCleanPath Response, so we put our own DER in there.

use anyhow::{Context, Result};
use ironrdp_acceptor::{Acceptor, AcceptorResult};
use ironrdp_connector::{ClientConnector, DesktopSize, Sequence};
use ironrdp_core::WriteBuf;
use ironrdp_pdu::nego::{
    ConnectionConfirm, ConnectionRequest, RequestFlags, ResponseFlags, SecurityProtocol,
};
use ironrdp_pdu::x224::X224;
use ironrdp_pdu::rdp::client_info::Credentials as AcceptorCredentials;
use ironrdp_rdcleanpath::{RDCleanPath, RDCleanPathPdu};
use ironrdp_tokio::reqwest::ReqwestNetworkClient;
use ironrdp_tokio::{FramedWrite, TokioFramed};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use crate::bridge::{ErasedStream, bridge_pdus_public};
use crate::caps::{acceptor_capabilities, default_desktop_size};
use crate::config::connector_config;
use crate::events::EventSender;

/// Peek at the first byte of the stream. Does not consume bytes.
pub async fn peek_first_byte(tcp: &TcpStream) -> Result<u8> {
    let mut buf = [0u8; 1];
    loop {
        match tcp.peek(&mut buf).await {
            Ok(n) if n == 1 => return Ok(buf[0]),
            Ok(0) => anyhow::bail!("peer closed before sending a byte"),
            Ok(_) => continue,
            Err(err) => return Err(err.into()),
        }
    }
}

/// Read one RDCleanPath PDU from the stream using DER length detection.
async fn read_rdcleanpath_pdu(tcp: &mut TcpStream) -> Result<RDCleanPathPdu> {
    let mut buf = Vec::with_capacity(512);
    loop {
        let mut chunk = [0u8; 512];
        let n = tcp
            .read(&mut chunk)
            .await
            .context("read RDCleanPath bytes")?;
        if n == 0 {
            anyhow::bail!("peer closed during RDCleanPath PDU read");
        }
        buf.extend_from_slice(&chunk[..n]);
        match RDCleanPathPdu::detect(&buf) {
            ironrdp_rdcleanpath::DetectionResult::Detected { total_length, .. } => {
                if buf.len() >= total_length {
                    if buf.len() > total_length {
                        warn!(
                            extra = buf.len() - total_length,
                            "extra bytes after RDCleanPath PDU; ignoring"
                        );
                        buf.truncate(total_length);
                    }
                    return RDCleanPathPdu::from_der(&buf).context("decode RDCleanPath PDU");
                }
            }
            ironrdp_rdcleanpath::DetectionResult::NotEnoughBytes => {}
            ironrdp_rdcleanpath::DetectionResult::Failed => {
                anyhow::bail!("not a valid RDCleanPath PDU");
            }
        }
        if buf.len() > 64 * 1024 {
            anyhow::bail!("RDCleanPath PDU exceeded 64KB while incomplete");
        }
    }
}

/// Read a TPKT-framed PDU (4-byte header with total length at bytes 2..4).
async fn read_tpkt_pdu<S>(framed: &mut TokioFramed<S>) -> Result<Vec<u8>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Sync + Unpin + 'static,
{
    let (stream, _leftover) = framed.get_inner_mut();
    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .await
        .context("read TPKT header")?;
    if header[0] != 0x03 {
        anyhow::bail!("not a TPKT frame: {:02x}", header[0]);
    }
    let total_len = u16::from_be_bytes([header[2], header[3]]) as usize;
    if total_len < 4 {
        anyhow::bail!("TPKT length too small");
    }
    let mut body = vec![0u8; total_len - 4];
    stream.read_exact(&mut body).await.context("read TPKT body")?;
    let mut full = Vec::with_capacity(total_len);
    full.extend_from_slice(&header);
    full.extend_from_slice(&body);
    Ok(full)
}

/// Encode a synthetic X.224 PDU (Connection Request or Confirm) into bytes
/// suitable for feeding into the acceptor or sending in the RDCleanPath Response.
fn encode_x224<T>(pdu: T) -> Result<Vec<u8>>
where
    T: ironrdp_core::Encode,
{
    let mut buf = WriteBuf::new();
    ironrdp_core::encode_buf(&pdu, &mut buf).context("encode X.224 PDU")?;
    Ok(buf.filled().to_vec())
}

/// Build a short-lived self-signed cert + a matching rustls ServerConfig.
/// The cert's DER goes into the RDCleanPath Response so the browser's TLS
/// validator accepts it; the ServerConfig terminates TLS on the WS side.
fn build_client_side_tls() -> Result<(Vec<u8>, Arc<tokio_rustls::rustls::ServerConfig>)> {
    let subject_alt_names = vec![
        "localhost".to_string(),
        "infisical-rdp-gateway".to_string(),
    ];
    let cert = rcgen::generate_simple_self_signed(subject_alt_names)
        .context("generate self-signed cert")?;
    let cert_der_vec = cert.cert.der().to_vec();
    let cert_der_for_tls = rustls::pki_types::CertificateDer::from(cert_der_vec.clone());
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
    let config = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der_for_tls], key_der)
        .context("build ServerConfig")?;
    Ok((cert_der_vec, Arc::new(config)))
}

/// Entry point for a browser session.
pub async fn handle_browser_session(
    mut client_tcp: TcpStream,
    target_host: &str,
    target_port: u16,
    username: &str,
    password: &str,
    tx: EventSender,
) -> Result<()> {
    // --- PHASE 1: RDCleanPath handshake ---

    let request_pdu = read_rdcleanpath_pdu(&mut client_tcp)
        .await
        .context("read RDCleanPath Request")?;
    let request = request_pdu.into_enum().context("into_enum")?;
    let (x224_cr, destination) = match request {
        RDCleanPath::Request {
            destination,
            x224_connection_request,
            ..
        } => (x224_connection_request.as_bytes().to_vec(), destination),
        other => anyhow::bail!("expected RDCleanPath::Request, got {other:?}"),
    };
    info!(destination, "RDCleanPath: received Request");

    // --- PHASE 2: open target TCP, do X.224 using browser's original CR ---
    //
    // Target sees whatever protocols the browser advertised (usually
    // HYBRID_EX) and confirms one. We keep that exchange untouched on the
    // target side so the connector's CredSSP path works as in CLI mode.

    let target_tcp = TcpStream::connect((target_host, target_port))
        .await
        .context("tcp connect to target")?;
    let target_addr = target_tcp.local_addr().context("local_addr")?;
    let mut target_framed = TokioFramed::new(target_tcp);

    target_framed
        .write_all(&x224_cr)
        .await
        .context("write X.224 CR to target")?;
    let x224_cc_target = read_tpkt_pdu(&mut target_framed)
        .await
        .context("read X.224 CC")?;
    debug!(
        len = x224_cc_target.len(),
        "RDCleanPath: received X.224 CC from target"
    );

    // --- PHASE 3: TLS with target, keep stream and cert for connector ---

    let (initial_stream, leftover) = target_framed.into_inner();
    let (upgraded_stream, target_cert) = ironrdp_tls::upgrade(initial_stream, target_host)
        .await
        .context("TLS upgrade to target")?;

    // --- PHASE 4: fabricate SSL-only CC for browser ---
    //
    // The IronRDP WASM client treats WSS as the secure transport and
    // sends plaintext RDP immediately after the Response -- no TLS
    // handshake on the WS. We fabricate an SSL-only CC so the browser
    // skips CredSSP and goes straight to MCS Connect Initial, which
    // the server-side acceptor handles post-"SecurityUpgrade" without
    // needing an actual TLS session or a CredSSP server impl.
    //
    // The cert chain in the Response is ignored by the client when it
    // doesn't do TLS, but the PDU still requires *something*; we include
    // a throwaway self-signed DER.

    let (throwaway_cert_der, _unused_tls_config) =
        build_client_side_tls().context("build throwaway cert for RDCleanPath Response")?;

    let fake_cc_bytes = encode_x224(X224(ConnectionConfirm::Response {
        flags: ResponseFlags::empty(),
        protocol: SecurityProtocol::SSL,
    }))
    .context("encode fabricated SSL-only X.224 CC")?;

    let response = RDCleanPathPdu::new_response(
        format!("{target_host}:{target_port}"),
        fake_cc_bytes,
        vec![throwaway_cert_der],
    )
    .context("build RDCleanPath Response")?;
    let response_der = response.to_der().context("encode RDCleanPath Response")?;
    client_tcp
        .write_all(&response_der)
        .await
        .context("write RDCleanPath Response to client")?;
    info!("RDCleanPath: Response sent (SSL-only), now driving both sides");

    // --- PHASE 5: drive target-side connector to active state ---

    let config = connector_config(username.to_owned(), password.to_owned(), 1920, 1080);
    let mut connector = ClientConnector::new(config, target_addr);

    let mut scratch = WriteBuf::new();
    connector
        .step_no_input(&mut scratch)
        .context("synthesize connector X.224 CR")?;
    scratch.clear();
    connector
        .step(&x224_cc_target, &mut scratch)
        .context("feed X.224 CC to connector")?;
    scratch.clear();

    let should_upgrade = ironrdp_tokio::skip_connect_begin(&mut connector);
    let upgraded = ironrdp_tokio::mark_as_upgraded(should_upgrade, &mut connector);

    let target_erased: ErasedStream = Box::new(upgraded_stream);
    let mut target_upgraded_framed = TokioFramed::new_with_leftover(target_erased, leftover);

    let server_public_key = ironrdp_tls::extract_tls_server_public_key(&target_cert)
        .ok_or_else(|| anyhow::anyhow!("extract target public key"))?;

    let connection_result = ironrdp_tokio::connect_finalize(
        upgraded,
        connector,
        &mut target_upgraded_framed,
        &mut ReqwestNetworkClient::new(),
        ironrdp_connector::ServerName::new(target_host),
        server_public_key.to_owned(),
        None,
    )
    .await
    .context("target-side connect_finalize (CredSSP + active)")?;
    info!(
        width = connection_result.desktop_size.width,
        height = connection_result.desktop_size.height,
        "RDCleanPath: target-side reached active"
    );

    // --- PHASE 6: drive client-facing acceptor past X.224 to BasicSettings ---
    //
    // The acceptor needs to parse an X.224 CR to decide which security
    // protocol to use. We never let the browser's real CR through (the
    // RDCleanPath Request swallowed it), so we feed a fabricated SSL-only
    // CR. Two step() calls transition InitiationWaitRequest ->
    // InitiationSendConfirm -> SecurityUpgrade. Then
    // mark_security_upgrade_as_done() moves to BasicSettingsWaitInitial
    // (not Credssp, because we picked SSL).

    let (width, height) = default_desktop_size();
    let placeholder_creds = AcceptorCredentials {
        username: "infisical".to_owned(),
        password: "infisical".to_owned(),
        domain: None,
    };
    let mut acceptor = Acceptor::new(
        SecurityProtocol::SSL,
        DesktopSize { width, height },
        acceptor_capabilities(width, height),
        Some(placeholder_creds),
    );

    let fake_cr_bytes = encode_x224(X224(ConnectionRequest {
        nego_data: None,
        flags: RequestFlags::empty(),
        protocol: SecurityProtocol::SSL,
    }))
    .context("encode fabricated SSL-only X.224 CR")?;

    let mut acc_scratch = WriteBuf::new();
    // step 1: consume CR -> InitiationSendConfirm
    acceptor
        .step(&fake_cr_bytes, &mut acc_scratch)
        .context("acceptor: step(fake CR)")?;
    acc_scratch.clear();
    // step 2: emit CC (discarded) -> SecurityUpgrade
    acceptor
        .step(&[], &mut acc_scratch)
        .context("acceptor: step(empty to emit CC)")?;
    acc_scratch.clear();

    if acceptor.reached_security_upgrade().is_none() {
        anyhow::bail!("acceptor did not reach SecurityUpgrade after synthetic CR/CC");
    }
    acceptor.mark_security_upgrade_as_done();

    // No TLS on the client side -- the WASM sends plaintext RDP over
    // the WSS tunnel. Hand the raw TCP stream straight to the acceptor.
    let client_erased: ErasedStream = Box::new(client_tcp);
    let client_framed: TokioFramed<ErasedStream> = TokioFramed::new(client_erased);

    let (client_final_framed, acceptor_result): (TokioFramed<ErasedStream>, AcceptorResult) =
        ironrdp_acceptor::accept_finalize(client_framed, &mut acceptor)
            .await
            .context("acceptor: accept_finalize")?;
    info!(
        user_channel_id = acceptor_result.user_channel_id,
        io_channel_id = acceptor_result.io_channel_id,
        "RDCleanPath: client-side reached active"
    );

    // --- PHASE 8: hand off to bridge_pdus ---

    bridge_pdus_public(client_final_framed, target_upgraded_framed, tx).await
}
