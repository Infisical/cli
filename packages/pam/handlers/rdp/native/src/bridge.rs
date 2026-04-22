//! MITM bridge with post-CredSSP passthrough.
//!
//! We run the acceptor and connector only far enough to do credential
//! injection: accept client TLS + fixed-cred CredSSP on one side, connect
//! target TLS + real-cred CredSSP on the other. Once both CredSSP sequences
//! complete, we stop driving the IronRDP state machines and byte-forward
//! raw bytes between the two TLS streams. Client and target then negotiate
//! MCS, channels, capabilities, and share state directly with each other
//! through us, avoiding the feature-flag drift that breaks strict clients
//! (Windows App, mstsc) when acceptor and connector negotiate independently.

use std::sync::Arc;

use anyhow::{Context, Result};
use ironrdp_acceptor::{Acceptor, BeginResult};
use ironrdp_connector::credssp::{CredsspSequence, KerberosConfig};
use ironrdp_connector::sspi::credssp::ClientState;
use ironrdp_connector::sspi::generator::GeneratorState;
use ironrdp_connector::{ClientConnector, ClientConnectorState};
use ironrdp_pdu::ironrdp_core::WriteBuf;
use ironrdp_pdu::nego::SecurityProtocol;
use ironrdp_pdu::rdp::client_info::Credentials as AcceptorCredentials;
use ironrdp_tokio::reqwest::ReqwestNetworkClient;
use ironrdp_tokio::{FramedWrite, NetworkClient};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::info;

use crate::config::{connector_config, DEFAULT_HEIGHT, DEFAULT_WIDTH};

/// Fixed credential presented by the native client through the acceptor.
/// The real access gate is upstream (Infisical auth + the gateway tunnel);
/// this value only needs to match what the CLI bakes into the `.rdp` file.
pub const ACCEPTOR_USERNAME: &str = "infisical";
pub const ACCEPTOR_PASSWORD: &str = "infisical";

pub struct TargetEndpoint {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
}

/// Run a single RDP MITM session. Injects credentials at CredSSP and then
/// passes everything else through between the two TLS streams.
pub async fn run_mitm(client_tcp: TcpStream, target: TargetEndpoint) -> Result<()> {
    // rustls 0.23 requires an explicit crypto provider when more than one is
    // compiled in. Our tree pulls both `ring` (direct) and `aws-lc-rs`
    // (transitively from reqwest). Install ring as the default on first call;
    // subsequent calls return Err("already installed") which we ignore.
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Run the two halves concurrently so the client doesn't sit idle while
    // the target side completes CredSSP. Functionally either order works;
    // this is a latency optimization.
    let (acceptor_output, connector_output) =
        tokio::try_join!(run_acceptor_half(client_tcp), run_connector_half(target))?;

    let (mut client_stream, client_leftover) = acceptor_output;
    let (mut target_stream, target_leftover) = connector_output;

    if !client_leftover.is_empty() {
        target_stream
            .write_all(&client_leftover)
            .await
            .context("flush client leftover to target")?;
    }
    if !target_leftover.is_empty() {
        client_stream
            .write_all(&target_leftover)
            .await
            .context("flush target leftover to client")?;
    }

    // Flush anything the CredSSP phase left buffered before handing off to
    // copy_bidirectional. Belt-and-suspenders: tokio-rustls normally
    // flushes on write_all, but being explicit here avoids a subtle stall
    // if the final EarlyUserAuthResult PDU is sitting in the write buffer.
    client_stream
        .flush()
        .await
        .context("flush client stream before passthrough")?;
    target_stream
        .flush()
        .await
        .context("flush target stream before passthrough")?;

    // Passthrough: client and target negotiate MCS, channels, capabilities
    // and share state directly through us. Real RDP clients hard-close the
    // TCP connection on session end (no TLS close_notify), so rustls
    // returns an UnexpectedEof. We treat that specific error as a clean
    // shutdown; any other IO error propagates.
    match tokio::io::copy_bidirectional(&mut client_stream, &mut target_stream).await {
        Ok(_) => info!("session ended cleanly"),
        Err(e) if is_unexpected_eof(&e) => info!("session ended (peer hard-closed)"),
        Err(e) => return Err(e).context("passthrough copy_bidirectional"),
    }
    Ok(())
}

/// rustls 0.23 raises `UnexpectedEof` when a peer closes the TCP connection
/// without sending `close_notify`. That's normal RDP client behavior and
/// should not surface as a session error.
fn is_unexpected_eof(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::UnexpectedEof
}

/// Accept the inbound connection, upgrade to TLS, and run CredSSP with the
/// fixed acceptor credential. Stops there: MCS and everything after is the
/// passthrough phase's job. Returns the underlying TLS stream and any bytes
/// the framed reader buffered beyond CredSSP.
async fn run_acceptor_half(client_tcp: TcpStream) -> Result<(ErasedStream, bytes::BytesMut)> {
    let (server_tls, acceptor_public_key) =
        build_acceptor_tls().context("build acceptor TLS config")?;
    let server_tls = Arc::new(server_tls);

    let acceptor_framed = ironrdp_tokio::TokioFramed::new(client_tcp);
    let expected_creds = AcceptorCredentials {
        username: ACCEPTOR_USERNAME.to_owned(),
        password: ACCEPTOR_PASSWORD.to_owned(),
        domain: None,
    };
    // Capabilities and desktop size passed here are unused because we never
    // call `accept_finalize`. Acceptor::new requires them so we pass empty
    // / sentinel values.
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

/// Connect to the target, upgrade to TLS, and run CredSSP with the injected
/// credentials. Stops there. Returns the underlying TLS stream and any
/// bytes the framed reader buffered beyond CredSSP.
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

/// Drive the connector's CredSSP sequence to completion. Equivalent to
/// `perform_credssp_step` in `ironrdp-async`'s private module; replicated
/// here so we can stop before `connect_finalize` would start the MCS /
/// capability exchange (which is what we want client and target to do
/// directly via passthrough).
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

/// Build the acceptor's TLS config and return the server's public key for
/// use as CredSSP TLS channel binding material.
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
