use anyhow::{anyhow, Context, Result};
use bytes::BytesMut;
use ironrdp_acceptor::{
    accept_finalize, Acceptor, AcceptorResult, DesktopSize as AcceptorDesktopSize,
};
use ironrdp_connector::{ClientConnector, Sequence};
use ironrdp_core::{encode_buf, WriteBuf};
use ironrdp_pdu::nego::{
    ConnectionConfirm, ConnectionRequest, RequestFlags, ResponseFlags, SecurityProtocol,
};
use ironrdp_pdu::rdp::client_info::Credentials as AcceptorCredentials;
use ironrdp_pdu::x224::X224;
use ironrdp_rdcleanpath::{DetectionResult, RDCleanPath, RDCleanPathPdu};
use ironrdp_tokio::reqwest::ReqwestNetworkClient;
use ironrdp_tokio::{
    connect_finalize, mark_as_upgraded, skip_connect_begin, FramedWrite, TokioFramed,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::bridge::{bridge_pdus, ErasedStream, TargetEndpoint};
use crate::caps::{acceptor_capabilities, default_desktop_size};
use crate::config::connector_config_browser;
use crate::events::EventSender;

pub async fn run_mitm_rdcleanpath(
    client_tcp: TcpStream,
    target: TargetEndpoint,
    acceptor_username: String,
    cancel: CancellationToken,
    tx: EventSender,
) -> Result<()> {
    tokio::select! {
        result = handle_browser_session(client_tcp, target, acceptor_username, tx) => result,
        _ = cancel.cancelled() => {
            info!("rdcleanpath session canceled by caller");
            Ok(())
        }
    }
}

async fn handle_browser_session(
    mut client_tcp: TcpStream,
    target: TargetEndpoint,
    acceptor_username: String,
    tx: EventSender,
) -> Result<()> {
    info!(host = %target.host, port = target.port, "rdcleanpath: starting browser session");
    let _ = rustls::crypto::ring::default_provider().install_default();

    debug!("rdcleanpath: reading RDCleanPath request from client");
    let (request_pdu, client_leftover) = read_rdcleanpath_pdu(&mut client_tcp)
        .await
        .context("read RDCleanPath Request")?;
    debug!("rdcleanpath: received RDCleanPath request");
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

    debug!("rdcleanpath: connecting to target");
    let target_tcp = TcpStream::connect((target.host.as_str(), target.port))
        .await
        .with_context(|| format!("connect target {}:{}", target.host, target.port))?;
    debug!("rdcleanpath: target TCP connected");
    let target_addr = target_tcp.local_addr().context("local_addr")?;
    let mut target_framed = TokioFramed::new(target_tcp);

    target_framed
        .write_all(&x224_cr)
        .await
        .context("write X.224 CR to target")?;
    let x224_cc_target = read_tpkt_pdu(&mut target_framed)
        .await
        .context("read X.224 CC")?;
    debug!(len = x224_cc_target.len(), "received X.224 CC from target");

    let (initial_stream, leftover) = target_framed.into_inner();
    debug!("rdcleanpath: TLS upgrading target");
    let (upgraded_stream, target_cert) = ironrdp_tls::upgrade(initial_stream, &target.host)
        .await
        .context("TLS upgrade to target")?;
    debug!("rdcleanpath: target TLS upgraded");

    let throwaway_cert_der = generate_throwaway_cert().context("throwaway cert")?;

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
    debug!(
        len = response_der.len(),
        "rdcleanpath: sent RDCleanPath response"
    );

    let (width, height) = default_desktop_size();

    let config = connector_config_browser(
        target.username.clone(),
        target.password.clone(),
        target.domain.clone(),
        width,
        height,
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
    let upgraded = mark_as_upgraded(should_upgrade, &mut connector);

    let target_erased: ErasedStream = Box::new(upgraded_stream);
    let mut target_upgraded_framed = TokioFramed::new_with_leftover(target_erased, leftover);

    let server_public_key = ironrdp_tls::extract_tls_server_public_key(&target_cert)
        .ok_or_else(|| anyhow!("extract target public key"))?;

    debug!("rdcleanpath: running connect_finalize on target");
    let connection_result = connect_finalize(
        upgraded,
        connector,
        &mut target_upgraded_framed,
        &mut ReqwestNetworkClient::new(),
        ironrdp_connector::ServerName::new(&target.host),
        server_public_key.to_owned(),
        None,
    )
    .await
    .map_err(|e| anyhow!("target connect_finalize: {e:?}"))?;
    info!(
        width = connection_result.desktop_size.width,
        height = connection_result.desktop_size.height,
        "rdcleanpath: target reached active stage"
    );

    let placeholder_creds = AcceptorCredentials {
        username: if acceptor_username.is_empty() {
            "infisical".to_owned()
        } else {
            acceptor_username
        },
        password: "infisical".to_owned(),
        domain: None,
    };
    let mut acceptor = Acceptor::new(
        SecurityProtocol::SSL,
        AcceptorDesktopSize { width, height },
        acceptor_capabilities(width, height),
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
    acc_scratch.clear();

    if acceptor.reached_security_upgrade().is_none() {
        anyhow::bail!("acceptor did not reach SecurityUpgrade after synthetic CR/CC");
    }
    acceptor.mark_security_upgrade_as_done();

    let client_erased: ErasedStream = Box::new(client_tcp);
    let client_framed: TokioFramed<ErasedStream> =
        TokioFramed::new_with_leftover(client_erased, client_leftover);

    debug!("rdcleanpath: running accept_finalize on client");
    let (client_final_framed, acceptor_result): (TokioFramed<ErasedStream>, AcceptorResult) =
        accept_finalize(client_framed, &mut acceptor)
            .await
            .map_err(|e| anyhow!("accept_finalize: {e:?}"))?;
    info!(
        user_ch = acceptor_result.user_channel_id,
        io_ch = acceptor_result.io_channel_id,
        "rdcleanpath: client reached active stage"
    );

    debug!("rdcleanpath: bridging PDUs");
    bridge_pdus(client_final_framed, target_upgraded_framed, tx).await
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

fn generate_throwaway_cert() -> Result<Vec<u8>> {
    let subject_alt_names = vec!["localhost".to_string(), "infisical-rdp-gateway".to_string()];
    let cert = rcgen::generate_simple_self_signed(subject_alt_names)
        .context("generate self-signed cert")?;
    Ok(cert.cert.der().to_vec())
}
