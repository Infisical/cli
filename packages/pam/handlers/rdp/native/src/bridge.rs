//! MITM bridge. Runs acceptor + connector only through CredSSP (to inject
//! credentials), then byte-forwards between the two TLS streams. Letting
//! client and target negotiate MCS/capabilities/share-state directly
//! avoids drift that breaks strict clients (Windows App, mstsc).

use std::sync::Arc;

use anyhow::{Context, Result};
use ironrdp_acceptor::{Acceptor, BeginResult};
use ironrdp_connector::credssp::{CredsspSequence, KerberosConfig};
use ironrdp_connector::sspi::credssp::ClientState;
use ironrdp_connector::sspi::generator::GeneratorState;
use ironrdp_connector::{encode_x224_packet, ClientConnector, ClientConnectorState};
use ironrdp_pdu::gcc::ConferenceCreateRequest;
use ironrdp_pdu::ironrdp_core::{decode, WriteBuf};
use ironrdp_pdu::mcs::ConnectInitial;
use ironrdp_pdu::nego::SecurityProtocol;
use ironrdp_pdu::rdp::client_info::Credentials as AcceptorCredentials;
use ironrdp_pdu::x224::{X224Data, X224};
use ironrdp_tokio::reqwest::ReqwestNetworkClient;
use ironrdp_tokio::{FramedWrite, NetworkClient};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::config::{connector_config, DEFAULT_HEIGHT, DEFAULT_WIDTH};

// Empty password for acceptor - the username comes from target credentials.
pub const ACCEPTOR_PASSWORD: &str = "";

pub struct TargetEndpoint {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    // Username the user types into their RDP client. Distinct from
    // `username` (the real Windows account injected to the target).
    // Falls back to `username` if empty.
    pub acceptor_username: String,
}

pub async fn run_mitm(
    client_tcp: TcpStream,
    target: TargetEndpoint,
    cancel: CancellationToken,
) -> Result<()> {
    tokio::select! {
        result = run_mitm_inner(client_tcp, target) => result,
        _ = cancel.cancelled() => {
            info!("session canceled by caller");
            Ok(())
        }
    }
}

async fn run_mitm_inner(client_tcp: TcpStream, target: TargetEndpoint) -> Result<()> {
    // Our tree pulls both ring (direct) and aws-lc-rs (via reqwest); rustls
    // 0.23 needs an explicit provider when more than one is compiled in.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let acceptor_username = if target.acceptor_username.is_empty() {
        target.username.clone()
    } else {
        target.acceptor_username.clone()
    };
    let (acceptor_output, connector_output) =
        tokio::try_join!(run_acceptor_half(client_tcp, acceptor_username), run_connector_half(target))?;

    let (mut client_stream, client_leftover) = acceptor_output;
    let (mut target_stream, target_leftover) = connector_output;

    // Strip virtual channels (clipboard, drives, audio, USB, etc.) from the
    // client's MCS Connect Initial before forwarding. Mouse/keyboard/screen
    // ride the implicit MCS I/O channel, not virtual channels, so they're
    // unaffected.
    filter_client_mcs_connect_initial(&mut client_stream, &mut target_stream, client_leftover)
        .await
        .context("filter client MCS Connect Initial")?;

    if !target_leftover.is_empty() {
        client_stream
            .write_all(&target_leftover)
            .await
            .context("flush target leftover to client")?;
    }

    // Explicit flush before passthrough: avoids a stall if the final
    // EarlyUserAuthResult PDU is sitting in the write buffer.
    client_stream
        .flush()
        .await
        .context("flush client stream before passthrough")?;
    target_stream
        .flush()
        .await
        .context("flush target stream before passthrough")?;

    // Real RDP clients hard-close TCP without TLS close_notify, which
    // rustls surfaces as UnexpectedEof. Treat that as clean shutdown.
    match tokio::io::copy_bidirectional(&mut client_stream, &mut target_stream).await {
        Ok(_) => info!("session ended cleanly"),
        Err(e) if is_unexpected_eof(&e) => info!("session ended (peer hard-closed)"),
        Err(e) => return Err(e).context("passthrough copy_bidirectional"),
    }
    Ok(())
}

fn is_unexpected_eof(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::UnexpectedEof
}

// Reads the client's MCS Connect Initial PDU, removes any virtual channels
// declared in its Client Network Data block, and forwards the rewritten PDU
// to the target. Any bytes after the PDU (rare; PDUs typically arrive one at
// a time at this stage) are forwarded unchanged.
async fn filter_client_mcs_connect_initial(
    client_stream: &mut ErasedStream,
    target_stream: &mut ErasedStream,
    leftover: bytes::BytesMut,
) -> Result<()> {
    let mut buf: Vec<u8> = leftover.to_vec();

    // TPKT header: 0x03 0x00 [len_hi] [len_lo], len includes the header.
    while buf.len() < 4 {
        let mut chunk = [0u8; 1024];
        let n = client_stream
            .read(&mut chunk)
            .await
            .context("read TPKT header")?;
        if n == 0 {
            anyhow::bail!("EOF before TPKT header for MCS Connect Initial");
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    if buf[0] != 0x03 {
        anyhow::bail!("expected TPKT version 3, got 0x{:02x}", buf[0]);
    }
    let total_len = usize::from(u16::from_be_bytes([buf[2], buf[3]]));

    while buf.len() < total_len {
        let mut chunk = vec![0u8; (total_len - buf.len()).max(1024)];
        let n = client_stream
            .read(&mut chunk)
            .await
            .context("read MCS Connect Initial body")?;
        if n == 0 {
            anyhow::bail!("EOF mid MCS Connect Initial");
        }
        buf.extend_from_slice(&chunk[..n]);
    }

    let pdu_bytes = &buf[..total_len];
    let extra_bytes: Vec<u8> = buf[total_len..].to_vec();

    let x224 = decode::<X224<X224Data<'_>>>(pdu_bytes)
        .map_err(|e| anyhow::anyhow!("decode X.224 wrapper: {e:?}"))?;
    let mut connect_initial = decode::<ConnectInitial>(x224.0.data.as_ref())
        .map_err(|e| anyhow::anyhow!("decode MCS Connect Initial: {e:?}"))?;

    let mut gcc_blocks = connect_initial.conference_create_request.into_gcc_blocks();
    if let Some(network) = gcc_blocks.network.as_mut() {
        let stripped: Vec<String> = network
            .channels
            .iter()
            .map(|c| c.name.as_str().unwrap_or("?").to_owned())
            .collect();
        if !stripped.is_empty() {
            info!(?stripped, "stripped virtual channels from MCS Connect Initial");
            network.channels.clear();
        }
    }
    connect_initial.conference_create_request = ConferenceCreateRequest::new(gcc_blocks)
        .map_err(|e| anyhow::anyhow!("rebuild ConferenceCreateRequest: {e:?}"))?;

    let mut out = WriteBuf::new();
    encode_x224_packet(&connect_initial, &mut out)
        .map_err(|e| anyhow::anyhow!("re-encode MCS Connect Initial: {e:?}"))?;

    target_stream
        .write_all(out.filled())
        .await
        .context("write filtered MCS Connect Initial to target")?;
    if !extra_bytes.is_empty() {
        target_stream
            .write_all(&extra_bytes)
            .await
            .context("forward bytes trailing MCS Connect Initial")?;
    }
    Ok(())
}

async fn run_acceptor_half(client_tcp: TcpStream, username: String) -> Result<(ErasedStream, bytes::BytesMut)> {
    let (server_tls, acceptor_public_key) =
        build_acceptor_tls().context("build acceptor TLS config")?;
    let server_tls = Arc::new(server_tls);

    let acceptor_framed = ironrdp_tokio::TokioFramed::new(client_tcp);
    let expected_creds = AcceptorCredentials {
        username,
        password: ACCEPTOR_PASSWORD.to_owned(),
        domain: None,
    };
    // Capabilities/desktop-size are shape-fillers; we never call accept_finalize.
    let mut acceptor = Acceptor::new(
        SecurityProtocol::HYBRID_EX | SecurityProtocol::HYBRID | SecurityProtocol::SSL,
        ironrdp_acceptor::DesktopSize {
            width: DEFAULT_WIDTH,
            height: DEFAULT_HEIGHT,
        },
        Vec::new(),
        Some(expected_creds),
    );

    let begin_result = ironrdp_acceptor::accept_begin(acceptor_framed, &mut acceptor)
        .await
        .context("acceptor: accept_begin")?;

    let mut acceptor_framed: ironrdp_tokio::TokioFramed<ErasedStream> = match begin_result {
        BeginResult::Continue(framed) => {
            let (stream, leftover) = framed.into_inner();
            let erased: ErasedStream = Box::new(stream);
            ironrdp_tokio::TokioFramed::new_with_leftover(erased, leftover)
        }
        BeginResult::ShouldUpgrade(tcp) => {
            let tls_stream = tokio_rustls::TlsAcceptor::from(server_tls)
                .accept(tcp)
                .await
                .context("acceptor: TLS accept")?;
            acceptor.mark_security_upgrade_as_done();
            let erased: ErasedStream = Box::new(tls_stream);
            ironrdp_tokio::TokioFramed::new(erased)
        }
    };

    if acceptor.should_perform_credssp() {
        ironrdp_acceptor::accept_credssp(
            &mut acceptor_framed,
            &mut acceptor,
            &mut ReqwestNetworkClient::new(),
            ironrdp_connector::ServerName::new("infisical-rdp-bridge"),
            acceptor_public_key,
            None,
        )
        .await
        .context("acceptor: CredSSP")?;
    }
    info!("acceptor: CredSSP complete");

    Ok(acceptor_framed.into_inner())
}

async fn run_connector_half(target: TargetEndpoint) -> Result<(ErasedStream, bytes::BytesMut)> {
    let target_addr = format!("{}:{}", target.host, target.port);
    let target_tcp = TcpStream::connect(&target_addr)
        .await
        .with_context(|| format!("connector: tcp connect to {target_addr}"))?;
    let client_addr = target_tcp.local_addr().context("connector: local_addr")?;

    let mut target_framed = ironrdp_tokio::TokioFramed::new(target_tcp);
    let config = connector_config(target.username.clone(), target.password.clone());
    let mut connector = ClientConnector::new(config, client_addr);

    let should_upgrade = ironrdp_tokio::connect_begin(&mut target_framed, &mut connector)
        .await
        .context("connector: connect_begin")?;

    let (initial_stream, leftover) = target_framed.into_inner();
    let (upgraded_stream, tls_cert) = ironrdp_tls::upgrade(initial_stream, &target.host)
        .await
        .context("connector: TLS upgrade")?;

    let _upgraded = ironrdp_tokio::mark_as_upgraded(should_upgrade, &mut connector);
    let erased: ErasedStream = Box::new(upgraded_stream);
    let mut target_framed = ironrdp_tokio::TokioFramed::new_with_leftover(erased, leftover);

    let server_public_key = ironrdp_tls::extract_tls_server_public_key(&tls_cert)
        .ok_or_else(|| anyhow::anyhow!("connector: extract TLS server public key"))?
        .to_vec();

    if connector.should_perform_credssp() {
        perform_connector_credssp(
            &mut connector,
            &mut target_framed,
            &mut ReqwestNetworkClient::new(),
            ironrdp_connector::ServerName::new(&target.host),
            server_public_key,
            None,
        )
        .await
        .context("connector: CredSSP")?;
    }
    info!("connector: CredSSP complete, credential injection succeeded");

    Ok(target_framed.into_inner())
}

// Replicated from ironrdp-async's private perform_credssp_step so we can
// stop before connect_finalize (which would start MCS/capability exchange).
async fn perform_connector_credssp<S>(
    connector: &mut ClientConnector,
    framed: &mut ironrdp_tokio::TokioFramed<S>,
    network_client: &mut ReqwestNetworkClient,
    server_name: ironrdp_connector::ServerName,
    server_public_key: Vec<u8>,
    kerberos_config: Option<KerberosConfig>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    let selected_protocol = match connector.state {
        ClientConnectorState::Credssp { selected_protocol } => selected_protocol,
        _ => anyhow::bail!("connector not in Credssp state"),
    };

    let (mut sequence, mut ts_request) = CredsspSequence::init(
        connector.config.credentials.clone(),
        connector.config.domain.as_deref(),
        selected_protocol,
        server_name,
        server_public_key,
        kerberos_config,
    )
    .context("CredsspSequence::init")?;

    let mut buf = WriteBuf::new();

    loop {
        let client_state: ClientState = {
            let mut generator = sequence.process_ts_request(ts_request);
            let mut state = generator.start();
            loop {
                match state {
                    GeneratorState::Suspended(request) => {
                        let response = network_client
                            .send(&request)
                            .await
                            .context("CredSSP network request")?;
                        state = generator.resume(Ok(response));
                    }
                    GeneratorState::Completed(result) => {
                        break result.map_err(|e| anyhow::anyhow!("CredSSP process: {e:?}"))?;
                    }
                }
            }
        };

        buf.clear();
        let written = sequence
            .handle_process_result(client_state, &mut buf)
            .context("CredsspSequence::handle_process_result")?;

        if let Some(response_len) = written.size() {
            framed
                .write_all(&buf[..response_len])
                .await
                .context("write CredSSP response")?;
        }

        let Some(next_pdu_hint) = sequence.next_pdu_hint() else {
            break;
        };

        let pdu = framed
            .read_by_hint(next_pdu_hint)
            .await
            .context("read CredSSP PDU")?;

        if let Some(next_request) = sequence
            .decode_server_message(&pdu)
            .context("CredsspSequence::decode_server_message")?
        {
            ts_request = next_request;
        } else {
            break;
        }
    }

    connector.mark_credssp_as_done();
    Ok(())
}

fn build_acceptor_tls() -> Result<(tokio_rustls::rustls::ServerConfig, Vec<u8>)> {
    use x509_cert::der::Decode;

    let subject_alt_names = vec!["localhost".to_string(), "infisical-rdp-bridge".to_string()];
    let cert =
        rcgen::generate_simple_self_signed(subject_alt_names).context("rcgen self-signed cert")?;

    let cert_der = cert.cert.der().clone();
    let parsed =
        x509_cert::Certificate::from_der(cert_der.as_ref()).context("parse self-signed cert")?;
    let public_key = ironrdp_tls::extract_tls_server_public_key(&parsed)
        .ok_or_else(|| anyhow::anyhow!("extract public key from self-signed cert"))?
        .to_vec();

    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
    let config = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .context("rustls ServerConfig")?;

    Ok((config, public_key))
}

pub trait AsyncReadWrite: AsyncRead + AsyncWrite {}
impl<T> AsyncReadWrite for T where T: AsyncRead + AsyncWrite {}

pub type ErasedStream = Box<dyn AsyncReadWrite + Send + Sync + Unpin + 'static>;
