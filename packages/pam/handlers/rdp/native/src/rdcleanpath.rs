//! RDCleanPath browser-flow handler for the gateway.
//!
//! After the RDCleanPath handshake, converges with the CLI flow by
//! driving an acceptor (client-facing) and a connector (target-facing)
//! to the active phase, then handing off to the existing bridge_pdus
//! loop for event-tapped byte forwarding.

use anyhow::{Context, Result};
use ironrdp_acceptor::{Acceptor, AcceptorResult};
use ironrdp_connector::{ClientConnector, DesktopSize, Sequence};
use ironrdp_core::WriteBuf;
use ironrdp_pdu::nego::SecurityProtocol;
use ironrdp_pdu::rdp::client_info::Credentials as AcceptorCredentials;
use ironrdp_rdcleanpath::der::Encode;
use ironrdp_rdcleanpath::{RDCleanPath, RDCleanPathPdu};
use ironrdp_tokio::reqwest::ReqwestNetworkClient;
use ironrdp_tokio::{FramedWrite, TokioFramed};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use crate::bridge::{bridge_pdus_public, ErasedStream};
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
                    return RDCleanPathPdu::from_der(&buf)
                        .context("decode RDCleanPath PDU");
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
    // Use a direct-TCP approach isn't great here since framed wraps the stream.
    // Instead, pull raw bytes through the inner stream.
    // For our use case we read the first TPKT frame then hand the stream back.
    let (stream, _leftover) = framed.get_inner_mut();
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await.context("read TPKT header")?;
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

    // --- PHASE 2: open target TCP, do X.224 manually using browser's CR ---
    // We use the browser's exact X.224 CR bytes to negotiate with the target,
    // so the negotiated protocol matches what the browser advertised. The
    // X.224 CC we receive goes back in the RDCleanPath Response.

    let target_tcp = TcpStream::connect((target_host, target_port))
        .await
        .context("tcp connect to target")?;
    let target_addr = target_tcp.local_addr().context("local_addr")?;
    let mut target_framed = TokioFramed::new(target_tcp);

    // Write the browser's X.224 CR, read target's X.224 CC.
    target_framed
        .write_all(&x224_cr)
        .await
        .context("write X.224 CR to target")?;
    let x224_cc = read_tpkt_pdu(&mut target_framed).await.context("read X.224 CC")?;
    debug!(len = x224_cc.len(), "RDCleanPath: received X.224 CC");

    // --- PHASE 3: TLS with target, extract cert ---

    let (initial_stream, leftover) = target_framed.into_inner();
    let (upgraded_stream, target_cert) = ironrdp_tls::upgrade(initial_stream, target_host)
        .await
        .context("TLS upgrade to target")?;
    let target_cert_der = target_cert.to_der().context("encode cert to DER")?;

    // --- PHASE 4: send RDCleanPath Response to browser ---

    let response = RDCleanPathPdu::new_response(
        format!("{}:{}", target_host, target_port),
        x224_cc.clone(),
        vec![target_cert_der],
    )
    .context("build RDCleanPath Response")?;
    let response_der = response.to_der().context("encode RDCleanPath Response")?;
    client_tcp
        .write_all(&response_der)
        .await
        .context("write RDCleanPath Response to client")?;
    info!("RDCleanPath: Response sent, now driving active-phase handshake");

    // --- PHASE 5: drive target-side connector to active state ---
    //
    // The connector's state machine expects to have generated its own X.224
    // CR and received its own X.224 CC. We've already done both manually,
    // using the browser's CR + target's CC. We synthesize those state
    // transitions on the connector:
    //   step_no_input -> connector emits an X.224 CR (discarded)
    //   step(x224_cc) -> connector consumes our CC, advances to
    //                    EnhancedSecurityUpgrade state
    //   skip_connect_begin + mark_as_upgraded -> past TLS
    //   connect_finalize -> runs CredSSP (with vaulted creds) + rest

    let config = connector_config(username.to_owned(), password.to_owned(), 1920, 1080);
    let mut connector = ClientConnector::new(config, target_addr);

    let mut scratch = WriteBuf::new();
    connector
        .step_no_input(&mut scratch)
        .context("synthesize connector X.224 CR")?;
    scratch.clear();
    connector
        .step(&x224_cc, &mut scratch)
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

    // --- PHASE 6: drive client-facing acceptor to active state ---
    //
    // The browser is past RDCleanPath from its perspective -- meaning it
    // thinks X.224 + TLS are done. Its next bytes will be whatever comes
    // after the selected security mode. We mirror this by running an
    // acceptor that's forced past its pre-TLS states without actually
    // doing TLS on this socket. Trick: feed the browser's X.224 CR back
    // into the acceptor (swallowing its CC output), then call
    // mark_security_upgrade_as_done().

    let mut client_framed: TokioFramed<ErasedStream> = {
        let erased: ErasedStream = Box::new(client_tcp);
        TokioFramed::new(erased)
    };

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

    // Prime the acceptor with the browser's X.224 CR. The acceptor will
    // generate an X.224 CC in its output buffer -- we discard it because
    // we already sent our own CC inside the RDCleanPath Response.
    let mut acceptor_scratch = WriteBuf::new();
    acceptor
        .step(&x224_cr, &mut acceptor_scratch)
        .context("acceptor: step with browser X.224 CR")?;
    acceptor_scratch.clear();

    // Acceptor should now be in SecurityUpgrade state. Mark it done.
    if acceptor.reached_security_upgrade().is_none() {
        anyhow::bail!("acceptor did not reach SecurityUpgrade after synthetic CR");
    }
    acceptor.mark_security_upgrade_as_done();

    // Drive the rest of the acceptor (post-TLS): ClientInfoPdu, Licensing,
    // Capabilities, Finalization. Reuses the existing accept_finalize.
    let (client_final_framed, acceptor_result): (TokioFramed<ErasedStream>, AcceptorResult) =
        ironrdp_acceptor::accept_finalize(client_framed, &mut acceptor)
            .await
            .context("acceptor: accept_finalize")?;
    info!(
        user_channel_id = acceptor_result.user_channel_id,
        io_channel_id = acceptor_result.io_channel_id,
        "RDCleanPath: client-side reached active"
    );
    client_framed = client_final_framed;

    // --- PHASE 7: hand off to bridge_pdus ---

    bridge_pdus_public(client_framed, target_upgraded_framed, tx).await
}
