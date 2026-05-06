//! MITM bridge. Runs acceptor + connector through CredSSP only, then byte-
//! forwards. Letting client/target negotiate MCS directly avoids drift
//! that breaks strict clients (Windows App, mstsc).

use std::borrow::Cow;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use ironrdp_acceptor::{Acceptor, BeginResult};
use ironrdp_connector::credssp::{CredsspSequence, KerberosConfig};
use ironrdp_connector::sspi::credssp::ClientState;
use ironrdp_connector::sspi::generator::GeneratorState;
use ironrdp_connector::{encode_x224_packet, ClientConnector, ClientConnectorState};
use ironrdp_core::ReadCursor;
use ironrdp_pdu::gcc::ConferenceCreateRequest;
use ironrdp_pdu::input::fast_path::{FastPathInput, FastPathInputEvent};
use ironrdp_pdu::ironrdp_core::{decode, WriteBuf};
use ironrdp_pdu::mcs::{ConnectInitial, SendDataRequest};
use ironrdp_pdu::nego::SecurityProtocol;
use ironrdp_pdu::rdp::client_info::Credentials as AcceptorCredentials;
use ironrdp_pdu::rdp::headers::{ShareControlHeader, ShareControlPdu};
use ironrdp_pdu::x224::{X224Data, X224};
use ironrdp_pdu::Action;
use ironrdp_tokio::reqwest::ReqwestNetworkClient;
use ironrdp_tokio::{FramedWrite, NetworkClient};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::cap_filter;
use crate::config::{connector_config, DEFAULT_HEIGHT, DEFAULT_WIDTH};
use crate::events::{elapsed_ns_since, EventSender, SessionEvent};

/// Cap on c2t PDUs to inspect before giving up on the cap filter.
const CONFIRM_ACTIVE_SCAN_MAX_PDUS: usize = 32;
/// Wall-clock cap on the cap-filter scan window.
const CONFIRM_ACTIVE_SCAN_MAX_DURATION: Duration = Duration::from_secs(5);

// The acceptor side of the bridge expects the user to type the target
// username with an empty password. The real password is injected by the
// connector side from the PAM vault.
pub const ACCEPTOR_PASSWORD: &str = "";

pub struct TargetEndpoint {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
}

pub async fn run_mitm(
    client_tcp: TcpStream,
    target: TargetEndpoint,
    cancel: CancellationToken,
    tx: EventSender,
) -> Result<()> {
    tokio::select! {
        result = run_mitm_inner(client_tcp, target, tx) => result,
        _ = cancel.cancelled() => {
            info!("session canceled by caller");
            Ok(())
        }
    }
}

async fn run_mitm_inner(
    client_tcp: TcpStream,
    target: TargetEndpoint,
    tx: EventSender,
) -> Result<()> {
    // Our tree pulls both ring (direct) and aws-lc-rs (via reqwest); rustls
    // 0.23 needs an explicit provider when more than one is compiled in.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let acceptor_username = target.username.clone();
    let (acceptor_output, connector_output) = tokio::try_join!(
        run_acceptor_half(client_tcp, acceptor_username),
        run_connector_half(target)
    )?;

    let (mut client_stream, client_leftover) = acceptor_output;
    let (mut target_stream, target_leftover) = connector_output;

    // Strip virtual channels (clipboard, drives, audio, USB) from MCS Connect Initial.
    // Mouse/keyboard/screen ride the implicit I/O channel and are unaffected.
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

    // PDU-framed bridge with an event tap. read_pdu is pure TPKT/FastPath
    // framing (no state machine) so this preserves the "no MCS drift"
    // property of the byte-level copy_bidirectional it replaces.
    let client_framed = ironrdp_tokio::TokioFramed::new(client_stream);
    let target_framed = ironrdp_tokio::TokioFramed::new(target_stream);
    bridge_pdus(client_framed, target_framed, tx).await
}

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

    let c2t = async move {
        let mut cap_filter = CapFilterState::Scanning {
            started_at: Instant::now(),
            pdus_seen: 0,
            info_done: false,
            confirm_done: false,
        };
        loop {
            let (action, frame) = match client_read.read_pdu().await {
                Ok(v) => v,
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err::<_, anyhow::Error>(e.into()),
            };
            tap_client_to_target(action, &frame, started_at, &tx_c2t);

            let bytes_to_forward: Vec<u8> = match cap_filter.consider(action, &frame) {
                CapFilterDecision::Forward => frame.to_vec(),
                CapFilterDecision::Replace(modified) => modified,
            };
            target_write
                .write_all(&bytes_to_forward)
                .await
                .context("write client PDU to target")?;
        }
        Ok(())
    };

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
                .context("write target PDU to client")?;
        }
        Ok(())
    };

    match tokio::try_join!(c2t, t2c) {
        Ok(_) => {
            info!("session ended cleanly");
            Ok(())
        }
        Err(e) => Err(e).context("bridge_pdus"),
    }
}

/// One-shot c2t scan that patches Client Info + Client Confirm Active.
enum CapFilterState {
    Scanning {
        started_at: Instant,
        pdus_seen: usize,
        info_done: bool,
        confirm_done: bool,
    },
    Done,
}

enum CapFilterDecision {
    Forward,
    Replace(Vec<u8>),
}

impl CapFilterState {
    fn consider(&mut self, action: Action, frame: &[u8]) -> CapFilterDecision {
        let CapFilterState::Scanning {
            started_at,
            pdus_seen,
            info_done,
            confirm_done,
        } = self
        else {
            return CapFilterDecision::Forward;
        };

        if action != Action::X224 {
            return CapFilterDecision::Forward;
        }

        *pdus_seen += 1;
        if *pdus_seen > CONFIRM_ACTIVE_SCAN_MAX_PDUS
            || started_at.elapsed() > CONFIRM_ACTIVE_SCAN_MAX_DURATION
        {
            warn!(
                pdus_seen,
                info_done = *info_done,
                confirm_done = *confirm_done,
                "scan window exhausted before both filters fired"
            );
            *self = CapFilterState::Done;
            return CapFilterDecision::Forward;
        }

        // The two filters are disjoint, so a match short-circuits.
        if !*info_done {
            if let Some(modified) = try_filter_client_info(frame) {
                *info_done = true;
                let both_done = *info_done && *confirm_done;
                if both_done {
                    *self = CapFilterState::Done;
                }
                return CapFilterDecision::Replace(modified);
            }
        }
        if !*confirm_done {
            if let Some(modified) = try_filter_confirm_active(frame) {
                *confirm_done = true;
                let both_done = *info_done && *confirm_done;
                if both_done {
                    *self = CapFilterState::Done;
                }
                return CapFilterDecision::Replace(modified);
            }
        }
        CapFilterDecision::Forward
    }
}

#[derive(Debug, Clone, Copy)]
struct ByteRange {
    offset: usize,
    len: usize,
}

impl ByteRange {
    fn slice<'a>(&self, frame: &'a [u8]) -> &'a [u8] {
        &frame[self.offset..self.offset + self.len]
    }

    fn slice_mut<'a>(&self, frame: &'a mut [u8]) -> &'a mut [u8] {
        &mut frame[self.offset..self.offset + self.len]
    }
}

/// Locate `send_data.user_data` inside `frame`. Bails on Cow::Owned.
fn user_data_range_within(frame: &[u8], send_data: &SendDataRequest<'_>) -> Option<ByteRange> {
    let slice: &[u8] = match &send_data.user_data {
        Cow::Borrowed(s) => s,
        Cow::Owned(_) => return None,
    };
    let frame_start = frame.as_ptr() as usize;
    let slice_start = slice.as_ptr() as usize;
    if slice_start < frame_start || slice_start + slice.len() > frame_start + frame.len() {
        return None;
    }
    Some(ByteRange {
        offset: slice_start - frame_start,
        len: slice.len(),
    })
}

fn locate_client_info(frame: &[u8]) -> Option<ByteRange> {
    const SEC_INFO_PKT: u16 = 0x0040;
    let send_data = decode::<X224<SendDataRequest<'_>>>(frame).ok()?.0;
    let user_data = user_data_range_within(frame, &send_data)?;
    if user_data.len < 4 {
        return None;
    }
    let bytes = user_data.slice(frame);
    let sec_flags = u16::from_le_bytes([bytes[0], bytes[1]]);
    (sec_flags & SEC_INFO_PKT != 0).then_some(user_data)
}

struct ConfirmActiveLayout {
    user_data: ByteRange,
    caps_start_in_user_data: usize,
}

fn locate_confirm_active(frame: &[u8]) -> Option<ConfirmActiveLayout> {
    let send_data = decode::<X224<SendDataRequest<'_>>>(frame).ok()?.0;
    let share_control = decode::<ShareControlHeader>(send_data.user_data.as_ref()).ok()?;
    if !matches!(
        share_control.share_control_pdu,
        ShareControlPdu::ClientConfirmActive(_),
    ) {
        return None;
    }
    let user_data = user_data_range_within(frame, &send_data)?;
    let caps_start_in_user_data = parse_confirm_active_caps_start(user_data.slice(frame))?;
    Some(ConfirmActiveLayout {
        user_data,
        caps_start_in_user_data,
    })
}

/// MS-RDPBCGR 2.2.1.13.2.1: ShareControlHeader(10) + originatorId(2) +
/// sourceDescLen(2) + combinedLen(2) + sourceDescriptor(var) + numCaps(2) + pad(2)
fn parse_confirm_active_caps_start(user_data: &[u8]) -> Option<usize> {
    let mut p = 10 + 2;
    if user_data.len() < p + 4 {
        return None;
    }
    let source_desc_len = u16::from_le_bytes([user_data[p], user_data[p + 1]]) as usize;
    p += 4 + source_desc_len + 4;
    (p <= user_data.len()).then_some(p)
}

fn try_filter_client_info(frame: &[u8]) -> Option<Vec<u8>> {
    let user_data = locate_client_info(frame)?;
    let mut out = frame.to_vec();
    if !cap_filter::client_info::clear_compression(user_data.slice_mut(&mut out)) {
        return None;
    }
    debug!("Client Info PDU: cleared INFO_COMPRESSION + CompressionTypeMask");
    Some(out)
}

fn try_filter_confirm_active(frame: &[u8]) -> Option<Vec<u8>> {
    let layout = locate_confirm_active(frame)?;
    let user_data_bytes = layout.user_data.slice(frame);

    let mut order_body_offset_in_frame: Option<usize> = None;
    let mut codecs_body_offset_in_frame: Option<usize> = None;
    for cap in cap_filter::walk_caps(user_data_bytes, layout.caps_start_in_user_data) {
        let body_offset_in_frame = layout.user_data.offset + cap.body_offset_in_user_data;
        match cap.cap_type {
            cap_filter::cap_types::ORDER if cap.cap_len >= cap_filter::order_cap::BODY_LEN + 4 => {
                order_body_offset_in_frame = Some(body_offset_in_frame);
            }
            cap_filter::cap_types::BITMAP_CODECS
                if cap.cap_len >= cap_filter::bitmap_codecs_cap::MIN_BODY_LEN + 4 =>
            {
                codecs_body_offset_in_frame = Some(body_offset_in_frame);
            }
            _ => {}
        }
    }

    // Without Order patched, server emits unrenderable Orders.
    let order_offset = order_body_offset_in_frame?;
    let mut out = frame.to_vec();
    cap_filter::order_cap::clear_order_support(
        &mut out[order_offset..order_offset + cap_filter::order_cap::BODY_LEN],
    );
    if let Some(codecs_offset) = codecs_body_offset_in_frame {
        cap_filter::bitmap_codecs_cap::clear_codec_count(&mut out[codecs_offset..]);
    }
    debug!("Confirm Active: cleared Order support + BitmapCodecs count");
    Some(out)
}

fn tap_client_to_target(action: Action, frame: &[u8], started_at: Instant, tx: &EventSender) {
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
            // MouseEventEx, MouseEventRel, QoeEvent, SyncEvent: skip for now;
            // uncommon in normal sessions and not needed for replay V1.
            _ => continue,
        };
        // send error means the receiver was dropped (poll loop exited).
        // The bridge keeps forwarding bytes regardless.
        let _ = tx.send(session_event);
    }
}

fn tap_target_to_client(action: Action, frame: &[u8], started_at: Instant, tx: &EventSender) {
    let _ = tx.send(SessionEvent::TargetFrame {
        action,
        payload: frame.to_vec(),
        elapsed_ns: elapsed_ns_since(started_at),
    });
}

fn decode_fast_path_input(frame: &[u8]) -> anyhow::Result<FastPathInput> {
    use ironrdp_core::Decode as _;
    let mut cursor = ReadCursor::new(frame);
    FastPathInput::decode(&mut cursor).map_err(|e| anyhow::anyhow!("decode FastPathInput: {e}"))
}

// Strips virtual channels from the Client Network Data block of MCS Connect Initial.
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
            info!(
                ?stripped,
                "stripped virtual channels from MCS Connect Initial"
            );
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

async fn run_acceptor_half(
    client_tcp: TcpStream,
    username: String,
) -> Result<(ErasedStream, bytes::BytesMut)> {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic ConfirmActive user_data prefix:
    ///   ShareControlHeader(10) + originatorId(2) + sourceDescLen(2) +
    ///   combinedLen(2) + sourceDescriptor(source_desc_len) + numCaps(2) + pad(2)
    fn confirm_active_prefix(source_desc_len: usize) -> Vec<u8> {
        let mut buf = vec![0xAA_u8; 10 + 2];
        buf.extend_from_slice(&(source_desc_len as u16).to_le_bytes());
        buf.extend_from_slice(&0xBBBB_u16.to_le_bytes());
        buf.extend_from_slice(&vec![0xCC; source_desc_len]);
        buf.extend_from_slice(&0xDDDD_u16.to_le_bytes());
        buf.extend_from_slice(&0xEEEE_u16.to_le_bytes());
        buf
    }

    #[test]
    fn caps_start_after_variable_source_descriptor() {
        let user_data = confirm_active_prefix(6);
        let p = parse_confirm_active_caps_start(&user_data).expect("caps start");
        assert_eq!(p, 12 + 4 + 6 + 4);
        assert_eq!(p, user_data.len());
    }

    #[test]
    fn caps_start_works_when_source_descriptor_is_empty() {
        let user_data = confirm_active_prefix(0);
        let p = parse_confirm_active_caps_start(&user_data).expect("caps start");
        assert_eq!(p, 12 + 4 + 4);
    }

    #[test]
    fn caps_start_returns_none_when_header_truncated() {
        let user_data = vec![0u8; 15];
        assert!(parse_confirm_active_caps_start(&user_data).is_none());
    }

    #[test]
    fn caps_start_returns_none_when_source_desc_len_overflows() {
        let mut user_data = vec![0u8; 12];
        user_data.extend_from_slice(&9999_u16.to_le_bytes());
        user_data.extend_from_slice(&[0u8; 2]);
        assert!(parse_confirm_active_caps_start(&user_data).is_none());
    }
}
