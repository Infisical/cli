//! RDCleanPath handler for the gateway side of browser sessions.
//!
//! When the Rust bridge receives an inbound socket, the first byte tells
//! us what we're looking at:
//!   * 0x03 -- TPKT version, meaning raw RDP X.224. The CLI flow. Goes
//!             through our existing acceptor+connector MITM path.
//!   * 0x30 -- ASN.1 SEQUENCE, meaning an RDCleanPath Request. The
//!             browser flow. Handled here.
//!
//! This module parses the Request, performs the X.224 + TLS handshake
//! with the target, extracts the cert chain, and sends the Response.
//!
//! After the Response is sent, the session needs to hand off to a
//! post-TLS active-phase bridge (acceptor side: dummy CredSSP with
//! browser; connector side: real CredSSP with target using vaulted
//! creds; event tap in the middle). That hand-off is not implemented
//! in this commit and is the last missing piece for a working browser
//! flow. The session ends with an error after the Response is sent.

use anyhow::{Context, Result};
use ironrdp_core::{Decode, ReadCursor};
use ironrdp_rdcleanpath::der::Encode;
use ironrdp_rdcleanpath::{RDCleanPath, RDCleanPathPdu};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

/// Peek at the first byte of the stream to decide routing. Does not
/// consume bytes; subsequent reads will see the same bytes.
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

/// Read one full RDCleanPath PDU from the stream.
pub async fn read_pdu(tcp: &mut TcpStream) -> Result<RDCleanPathPdu> {
    use tokio::io::AsyncReadExt as _;

    // ASN.1 DER: first byte is the SEQUENCE tag (0x30), second and
    // following bytes encode the content length. We iteratively read
    // more bytes into a buffer and try to parse; once parsing succeeds
    // we stop.
    let mut buf = Vec::with_capacity(256);
    loop {
        // Read at least one more byte on each iteration.
        let mut chunk = [0u8; 256];
        let n = tcp
            .read(&mut chunk)
            .await
            .context("read RDCleanPath bytes")?;
        if n == 0 {
            anyhow::bail!("peer closed during RDCleanPath PDU read");
        }
        buf.extend_from_slice(&chunk[..n]);

        match RDCleanPathPdu::detect(&buf) {
            ironrdp_rdcleanpath::DetectionResult::Detected {
                total_length,
                ..
            } => {
                if buf.len() >= total_length {
                    // Drop any bytes past total_length back to the stream.
                    // (For RDCleanPath the PDU is always the first message,
                    // so buf should equal total_length exactly in practice.)
                    if buf.len() > total_length {
                        warn!(
                            extra = buf.len() - total_length,
                            "extra bytes after RDCleanPath PDU; ignoring"
                        );
                        buf.truncate(total_length);
                    }
                    let pdu = RDCleanPathPdu::from_der(&buf)
                        .context("decode RDCleanPath PDU")?;
                    return Ok(pdu);
                }
                // Need more bytes, keep reading.
            }
            ironrdp_rdcleanpath::DetectionResult::NotEnoughBytes => {
                // Keep reading.
            }
            ironrdp_rdcleanpath::DetectionResult::Failed => {
                anyhow::bail!("not a valid RDCleanPath PDU");
            }
        }

        if buf.len() > 64 * 1024 {
            anyhow::bail!("RDCleanPath PDU exceeded 64KB while incomplete");
        }
    }
}

/// Entry point for a browser session. Parses the Request, does the
/// target-side handshake, sends the Response, then bails with an error
/// (the active-phase bridge is not yet implemented).
pub async fn handle_browser_session(
    mut client_tcp: TcpStream,
    target_host: &str,
    target_port: u16,
    _username: &str,
    _password: &str,
) -> Result<()> {
    let request_pdu = read_pdu(&mut client_tcp).await.context("read RDCleanPath Request")?;

    let request = request_pdu.into_enum().context("into_enum")?;
    let (x224_cr, destination, _proxy_auth) = match request {
        RDCleanPath::Request {
            destination,
            proxy_auth,
            x224_connection_request,
            ..
        } => (
            x224_connection_request.as_bytes().to_vec(),
            destination,
            proxy_auth,
        ),
        other => anyhow::bail!("expected RDCleanPath::Request, got {other:?}"),
    };

    info!(destination, "RDCleanPath: received Request");

    // Open TCP to target.
    let mut target_tcp = TcpStream::connect((target_host, target_port))
        .await
        .context("tcp connect to target")?;

    // Forward X.224 CR, read X.224 CC.
    target_tcp
        .write_all(&x224_cr)
        .await
        .context("write X.224 CR to target")?;
    let x224_cc = read_x224_pdu(&mut target_tcp).await.context("read X.224 CC")?;
    debug!(len = x224_cc.len(), "RDCleanPath: received X.224 CC");

    // TLS handshake with target, extract cert chain.
    let (_tls_stream, target_cert) = ironrdp_tls::upgrade(target_tcp, target_host)
        .await
        .context("TLS upgrade to target")?;
    let cert_chain_der = target_cert
        .to_der()
        .context("encode target cert to DER")?;

    // Build + send Response.
    let response = RDCleanPathPdu::new_response(
        format!("{}:{}", target_host, target_port),
        x224_cc,
        vec![cert_chain_der],
    )
    .context("build RDCleanPath Response")?;
    let response_der = response.to_der().context("encode RDCleanPath Response")?;
    client_tcp
        .write_all(&response_der)
        .await
        .context("write RDCleanPath Response to client")?;
    info!("RDCleanPath: Response sent, handshake complete");

    // TODO(phase-4b): active-phase bridge. Needs:
    //   * An acceptor-like state machine on the client side that's
    //     already past X.224 + TLS (since RDCleanPath did both), ready
    //     for client's CredSSP and the Basic Settings Exchange.
    //   * A connector-like state machine on the target side that's
    //     already past TLS (we just did it above), ready to do CredSSP
    //     with injected credentials.
    //   * The existing event-tap bridge loop once both are in active.
    // IronRDP currently doesn't expose "start from post-TLS" entry
    // points for either Acceptor or ClientConnector. Need either a
    // narrow fork to add those, or a custom state machine that calls
    // the same primitives as the existing crates but from a different
    // starting state.
    anyhow::bail!(
        "RDCleanPath handshake completed; active-phase bridge is not implemented yet"
    )
}

async fn read_x224_pdu(tcp: &mut TcpStream) -> Result<Vec<u8>> {
    use tokio::io::AsyncReadExt as _;

    // TPKT header: 4 bytes. Bytes 2..4 carry the total PDU length.
    let mut header = [0u8; 4];
    tcp.read_exact(&mut header).await.context("read TPKT header")?;
    if header[0] != 0x03 {
        anyhow::bail!("not a TPKT frame: {:02x}", header[0]);
    }
    let total_len = u16::from_be_bytes([header[2], header[3]]) as usize;
    if total_len < 4 {
        anyhow::bail!("TPKT length too small: {}", total_len);
    }
    let mut body = vec![0u8; total_len - 4];
    tcp.read_exact(&mut body).await.context("read TPKT body")?;
    let mut full = Vec::with_capacity(total_len);
    full.extend_from_slice(&header);
    full.extend_from_slice(&body);

    // Validate it's a Connection Confirm by parsing with ironrdp-pdu.
    // (Cheap sanity check; not strictly needed for forwarding.)
    let mut cursor = ReadCursor::new(&full);
    if let Err(err) = <ironrdp_pdu::x224::X224<ironrdp_pdu::nego::ConnectionConfirm>>::decode(&mut cursor) {
        warn!(?err, "X.224 PDU did not decode as ConnectionConfirm; forwarding anyway");
    }

    Ok(full)
}
