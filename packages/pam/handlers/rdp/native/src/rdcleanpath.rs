use anyhow::{anyhow, Context, Result};
use bytes::BytesMut;
use ironrdp_acceptor::{Acceptor, DesktopSize as AcceptorDesktopSize};
use ironrdp_connector::{ClientConnector, Sequence};
use ironrdp_core::{encode_buf, WriteBuf};
use ironrdp_pdu::nego::{
    ConnectionConfirm, ConnectionRequest, RequestFlags, ResponseFlags, SecurityProtocol,
};
use ironrdp_pdu::rdp::client_info::Credentials as AcceptorCredentials;
use ironrdp_pdu::x224::X224;
use ironrdp_rdcleanpath::{DetectionResult, RDCleanPath, RDCleanPathPdu};
use ironrdp_tokio::reqwest::ReqwestNetworkClient;
use ironrdp_tokio::{mark_as_upgraded, skip_connect_begin, FramedWrite, TokioFramed};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::bridge::{
    bridge_pdus, build_acceptor_tls_with_cert, filter_client_mcs_connect_initial,
    perform_connector_credssp, ErasedStream, TargetEndpoint,
};
use crate::config::{connector_config, DEFAULT_HEIGHT, DEFAULT_WIDTH};
use crate::events::EventSender;

pub async fn run_mitm_rdcleanpath(
    client_tcp: TcpStream,
    target: TargetEndpoint,
    acceptor_username: String,
    cancel: CancellationToken,
    tx: EventSender,
) -> Result<()> {
    tokio::select! {
        result = run_mitm_rdcleanpath_inner(client_tcp, target, acceptor_username, tx) => result,
        _ = cancel.cancelled() => {
            info!("rdcleanpath session canceled by caller");
            Ok(())
        }
    }
}

/// Browser MITM flow for clients that speak RDCleanPath (IronRDP WASM).
///
/// 1. Read RDCleanPath Request from client, extract the X.224 CR (Connection Request).
/// 2. Forward CR to target, read CC (Connection Confirm), TLS-upgrade the target connection.
/// 3. Build a throwaway cert, wrap a fake CC + cert in an RDCleanPath Response, send to client.
/// 4. Advance connector past X.224, run CredSSP to the target.
/// 5. Advance acceptor with synthetic X.224 CR/CC, run CredSSP to the client.
/// 6. Bridge MCS/capabilities + PDUs (shared with the native path).
async fn run_mitm_rdcleanpath_inner(
    mut client_tcp: TcpStream,
    target: TargetEndpoint,
    acceptor_username: String,
    tx: EventSender,
) -> Result<()> {
    info!(host = %target.host, port = target.port, "rdcleanpath: starting browser session");
    let _ = rustls::crypto::ring::default_provider().install_default();

    let (request_pdu, client_leftover) = read_rdcleanpath_pdu(&mut client_tcp)
        .await
        .context("read RDCleanPath Request")?;
    let request = request_pdu
        .into_enum()
        .map_err(|e| anyhow!("RDCleanPath enum: {e}"))?;
    let (x224_cr, destination) = match request {
        RDCleanPath::Request {
            destination,
            x224_connection_request,
            ..
        } => (x224_connection_request.as_bytes().to_vec(), destination),
        other => anyhow::bail!("expected RDCleanPath::Request, got {other:?}"),
    };
    info!(destination, "RDCleanPath: received Request");

    let target_tcp = TcpStream::connect((target.host.as_str(), target.port))
        .await
        .with_context(|| format!("connect target {}:{}", target.host, target.port))?;
    let target_addr = target_tcp.local_addr().context("local_addr")?;
    let mut target_framed = TokioFramed::new(target_tcp);

    target_framed
        .write_all(&x224_cr)
        .await
        .context("write X.224 CR to target")?;
    let x224_cc_target = read_tpkt_pdu(&mut target_framed)
        .await
        .context("read X.224 CC")?;

    let (initial_stream, target_leftover) = target_framed.into_inner();
    let (upgraded_stream, target_cert) = ironrdp_tls::upgrade(initial_stream, &target.host)
        .await
        .context("TLS upgrade to target")?;

    let (_tls_config, acceptor_public_key, throwaway_cert_der) =
        build_acceptor_tls_with_cert().context("build throwaway cert")?;

    let fake_cc_bytes = encode_x224(X224(ConnectionConfirm::Response {
        flags: ResponseFlags::empty(),
        protocol: SecurityProtocol::SSL,
    }))
    .context("encode SSL-only X.224 CC")?;

    let response = RDCleanPathPdu::new_response(
        format!("{}:{}", target.host, target.port),
        fake_cc_bytes,
        std::iter::once(throwaway_cert_der),
    )
    .map_err(|e| anyhow!("build RDCleanPath Response: {e:?}"))?;
    let response_der = response
        .to_der()
        .map_err(|e| anyhow!("encode RDCleanPath Response: {e:?}"))?;
    client_tcp
        .write_all(&response_der)
        .await
        .context("write RDCleanPath Response to client")?;

    // --- Connector: advance past X.224, then CredSSP only ---

    let config = connector_config(
        target.username.clone(),
        target.password.clone(),
        target.domain.clone(),
    );
    let mut connector = ClientConnector::new(config, target_addr);

    let mut scratch = WriteBuf::new();
    connector
        .step_no_input(&mut scratch)
        .map_err(|e| anyhow!("connector step_no_input: {e:?}"))?;
    scratch.clear();
    connector
        .step(&x224_cc_target, &mut scratch)
        .map_err(|e| anyhow!("connector step CC: {e:?}"))?;

    let should_upgrade = skip_connect_begin(&mut connector);
    let _ = mark_as_upgraded(should_upgrade, &mut connector);

    let target_erased: ErasedStream = Box::new(upgraded_stream);
    let mut target_framed = TokioFramed::new_with_leftover(target_erased, target_leftover);

    let server_public_key = ironrdp_tls::extract_tls_server_public_key(&target_cert)
        .ok_or_else(|| anyhow!("extract target public key"))?;

    if connector.should_perform_credssp() {
        perform_connector_credssp(
            &mut connector,
            &mut target_framed,
            &mut ReqwestNetworkClient::new(),
            ironrdp_connector::ServerName::new(&target.host),
            server_public_key.to_vec(),
            None,
        )
        .await
        .context("connector: CredSSP")?;
    }
    info!("rdcleanpath: connector CredSSP complete");

    // --- Acceptor: advance past X.224, then CredSSP only ---

    let placeholder_creds = AcceptorCredentials {
        username: acceptor_username,
        password: "infisical".to_owned(),
        domain: None,
    };
    let mut acceptor = Acceptor::new(
        SecurityProtocol::SSL,
        AcceptorDesktopSize {
            width: DEFAULT_WIDTH,
            height: DEFAULT_HEIGHT,
        },
        Vec::new(),
        Some(placeholder_creds),
    );

    let fake_cr_bytes = encode_x224(X224(ConnectionRequest {
        nego_data: None,
        flags: RequestFlags::empty(),
        protocol: SecurityProtocol::SSL,
    }))
    .context("encode SSL-only X.224 CR")?;

    let mut acc_scratch = WriteBuf::new();
    acceptor
        .step(&fake_cr_bytes, &mut acc_scratch)
        .map_err(|e| anyhow!("acceptor step CR: {e:?}"))?;
    acc_scratch.clear();
    acceptor
        .step(&[], &mut acc_scratch)
        .map_err(|e| anyhow!("acceptor step empty: {e:?}"))?;

    if acceptor.reached_security_upgrade().is_none() {
        anyhow::bail!("acceptor did not reach SecurityUpgrade after synthetic CR/CC");
    }
    acceptor.mark_security_upgrade_as_done();

    let client_erased: ErasedStream = Box::new(client_tcp);
    let mut client_framed: TokioFramed<ErasedStream> =
        TokioFramed::new_with_leftover(client_erased, client_leftover);

    if acceptor.should_perform_credssp() {
        ironrdp_acceptor::accept_credssp(
            &mut client_framed,
            &mut acceptor,
            &mut ReqwestNetworkClient::new(),
            ironrdp_connector::ServerName::new("infisical-rdp-bridge"),
            acceptor_public_key,
            None,
        )
        .await
        .context("acceptor: CredSSP")?;
    }
    info!("rdcleanpath: acceptor CredSSP complete");

    // --- Bridge MCS/capabilities + PDUs (same as native path) ---

    let (mut client_stream, client_lo) = client_framed.into_inner();
    let (mut target_stream, target_lo) = target_framed.into_inner();

    filter_client_mcs_connect_initial(&mut client_stream, &mut target_stream, client_lo)
        .await
        .context("filter client MCS Connect Initial")?;

    if !target_lo.is_empty() {
        client_stream
            .write_all(&target_lo)
            .await
            .context("flush target leftover to client")?;
    }

    client_stream
        .flush()
        .await
        .context("flush client stream before passthrough")?;
    target_stream
        .flush()
        .await
        .context("flush target stream before passthrough")?;

    let client_framed = ironrdp_tokio::TokioFramed::new(client_stream);
    let target_framed = ironrdp_tokio::TokioFramed::new(target_stream);
    bridge_pdus(client_framed, target_framed, tx).await
}

const RDCLEANPATH_READ_TIMEOUT: Duration = Duration::from_secs(30);

async fn read_rdcleanpath_pdu(tcp: &mut TcpStream) -> Result<(RDCleanPathPdu, BytesMut)> {
    timeout(RDCLEANPATH_READ_TIMEOUT, read_rdcleanpath_pdu_inner(tcp))
        .await
        .map_err(|_| {
            anyhow!(
                "timed out waiting for RDCleanPath PDU ({}s)",
                RDCLEANPATH_READ_TIMEOUT.as_secs()
            )
        })?
}

/// Accumulates TCP reads until a complete DER-encoded RDCleanPath PDU is detected.
async fn read_rdcleanpath_pdu_inner(tcp: &mut TcpStream) -> Result<(RDCleanPathPdu, BytesMut)> {
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
            DetectionResult::Detected { total_length, .. } => {
                if buf.len() >= total_length {
                    let leftover = BytesMut::from(&buf[total_length..]);
                    buf.truncate(total_length);
                    let pdu = RDCleanPathPdu::from_der(&buf)
                        .map_err(|e| anyhow!("decode RDCleanPath PDU: {e:?}"))?;
                    return Ok((pdu, leftover));
                }
            }
            DetectionResult::NotEnoughBytes => {}
            DetectionResult::Failed => {
                anyhow::bail!("not a valid RDCleanPath PDU");
            }
        }
        if buf.len() > 64 * 1024 {
            anyhow::bail!("RDCleanPath PDU exceeded 64KB while incomplete");
        }
    }
}

/// Reads a single TPKT-framed PDU (4-byte header with big-endian length) from raw TCP.
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
    stream
        .read_exact(&mut body)
        .await
        .context("read TPKT body")?;
    let mut full = Vec::with_capacity(total_len);
    full.extend_from_slice(&header);
    full.extend_from_slice(&body);
    Ok(full)
}

fn encode_x224<T>(pdu: T) -> Result<Vec<u8>>
where
    T: ironrdp_core::Encode,
{
    let mut buf = WriteBuf::new();
    encode_buf(&pdu, &mut buf).map_err(|e| anyhow!("encode X.224 PDU: {e:?}"))?;
    Ok(buf.filled().to_vec())
}
