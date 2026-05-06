//! C ABI for the bridge. Each session runs on its own thread with a
//! current-thread tokio runtime. Caller contract: wait, then free.

use std::collections::HashMap;
use std::ffi::{c_char, CStr};
use std::net::TcpStream as StdTcpStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use crate::bridge::{run_mitm, TargetEndpoint};
use crate::events::{self, SessionEvent};

pub const RDP_BRIDGE_OK: i32 = 0;
pub const RDP_BRIDGE_SESSION_ERROR: i32 = 1;
pub const RDP_BRIDGE_THREAD_PANIC: i32 = 2;
pub const RDP_BRIDGE_INVALID_HANDLE: i32 = -1;
pub const RDP_BRIDGE_BAD_ARG: i32 = -2;
pub const RDP_BRIDGE_RUNTIME_ERROR: i32 = -3;

// Distinct number space from the bridge status codes above; consumed by
// a different Go function.
pub const RDP_POLL_OK: i32 = 0;
pub const RDP_POLL_TIMEOUT: i32 = 1;
pub const RDP_POLL_ENDED: i32 = 2;
pub const RDP_POLL_INVALID_HANDLE: i32 = -1;

#[repr(u8)]
pub enum RdpEventType {
    Keyboard = 1,
    Unicode = 2,
    Mouse = 3,
    TargetFrame = 4,
}

/// Fields are reused across variants; check `event_type` first.
/// For TargetFrame, `payload_ptr` is libc::malloc'd; Go must libc::free it.
#[repr(C)]
pub struct RdpEvent {
    pub event_type: u8,
    /// Nanoseconds since bridge start.
    pub elapsed_ns: u64,
    /// Keyboard: scancode. Unicode: code point. Mouse: x. TargetFrame: bytes.
    pub value_a: u32,
    /// Mouse: y. Others: 0.
    pub value_b: u32,
    /// Keyboard / Unicode / Mouse flags (raw bits from the RDP layer).
    pub flags: u32,
    /// Mouse wheel delta (signed). 0 for others.
    pub wheel_delta: i32,
    /// TargetFrame: 0 = X.224, 1 = FastPath. 0 for others.
    pub action: u8,
    pub payload_ptr: *mut u8,
    pub payload_len: u32,
}

impl RdpEvent {
    const fn zero() -> Self {
        Self {
            event_type: 0,
            elapsed_ns: 0,
            value_a: 0,
            value_b: 0,
            flags: 0,
            wheel_delta: 0,
            action: 0,
            payload_ptr: std::ptr::null_mut(),
            payload_len: 0,
        }
    }

    fn from_session_event(ev: SessionEvent) -> Self {
        match ev {
            SessionEvent::KeyboardInput {
                scancode,
                flags,
                elapsed_ns,
            } => Self {
                event_type: RdpEventType::Keyboard as u8,
                elapsed_ns,
                value_a: scancode.into(),
                flags: flags.bits().into(),
                ..Self::zero()
            },
            SessionEvent::UnicodeInput {
                code_point,
                flags,
                elapsed_ns,
            } => Self {
                event_type: RdpEventType::Unicode as u8,
                elapsed_ns,
                value_a: code_point.into(),
                flags: flags.bits().into(),
                ..Self::zero()
            },
            SessionEvent::MouseInput {
                x,
                y,
                flags,
                wheel_delta,
                elapsed_ns,
            } => Self {
                event_type: RdpEventType::Mouse as u8,
                elapsed_ns,
                value_a: x.into(),
                value_b: y.into(),
                flags: flags.bits().into(),
                wheel_delta: wheel_delta.into(),
                ..Self::zero()
            },
            SessionEvent::TargetFrame {
                action,
                payload,
                elapsed_ns,
            } => {
                // Copy into a libc::malloc'd buffer the Go caller will free.
                // Using libc (not Rust's allocator) lets Go free directly via
                // C.free without an extra trip back through the FFI.
                let len = payload.len();
                let ptr = if len == 0 {
                    std::ptr::null_mut()
                } else {
                    unsafe {
                        let p = libc::malloc(len) as *mut u8;
                        if p.is_null() {
                            std::ptr::null_mut()
                        } else {
                            std::ptr::copy_nonoverlapping(payload.as_ptr(), p, len);
                            p
                        }
                    }
                };
                Self {
                    event_type: RdpEventType::TargetFrame as u8,
                    elapsed_ns,
                    value_a: len as u32,
                    action: match action {
                        ironrdp_pdu::Action::X224 => 0,
                        ironrdp_pdu::Action::FastPath => 1,
                    },
                    payload_ptr: ptr,
                    payload_len: len as u32,
                    ..Self::zero()
                }
            }
        }
    }
}

struct BridgeEntry {
    cancel: CancellationToken,
    // Taken by wait(); None afterward.
    join: Mutex<Option<JoinHandle<anyhow::Result<()>>>>,
    // Receiver side of the bridge's event channel. Polled by Go via
    // rdp_bridge_poll_event. Wrapped in Option so the poll loop can take it
    // out for the duration of the await without holding the HANDLES lock.
    events_rx: Mutex<Option<mpsc::UnboundedReceiver<SessionEvent>>>,
    // Set once the events channel has reported closed; subsequent polls
    // short-circuit to RDP_POLL_ENDED.
    events_ended: Mutex<bool>,
}

static HANDLES: LazyLock<Mutex<HashMap<u64, BridgeEntry>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);

fn register(entry: BridgeEntry) -> u64 {
    let id = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    HANDLES.lock().expect("HANDLES poisoned").insert(id, entry);
    id
}

/// # Safety
///
/// `ptr` must be null or a valid NUL-terminated C string.
unsafe fn c_str_to_owned(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .ok()
        .map(str::to_owned)
}

fn spawn_session(
    client_tcp: StdTcpStream,
    host: String,
    port: u16,
    username: String,
    password: String,
) -> anyhow::Result<u64> {
    client_tcp.set_nonblocking(true)?;
    let cancel = CancellationToken::new();
    let cancel_for_thread = cancel.clone();

    let (events_tx, events_rx) = events::channel();

    let join = std::thread::Builder::new()
        .name("rdp-bridge-session".to_owned())
        .spawn(move || -> anyhow::Result<()> {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            rt.block_on(async move {
                let client = TcpStream::from_std(client_tcp)?;
                let endpoint = TargetEndpoint {
                    host,
                    port,
                    username,
                    password,
                };
                run_mitm(client, endpoint, cancel_for_thread, events_tx).await
            })
        })?;

    Ok(register(BridgeEntry {
        cancel,
        join: Mutex::new(Some(join)),
        events_rx: Mutex::new(Some(events_rx)),
        events_ended: Mutex::new(false),
    }))
}

/// # Safety
///
/// `client_fd` ownership transfers to the bridge on OK, stays with the
/// caller on error. Strings must be NUL-terminated valid UTF-8.
#[cfg(unix)]
#[no_mangle]
pub unsafe extern "C" fn rdp_bridge_start_unix_fd(
    client_fd: std::ffi::c_int,
    target_host: *const c_char,
    target_port: u16,
    username: *const c_char,
    password: *const c_char,
    out_handle: *mut u64,
) -> i32 {
    if out_handle.is_null() {
        return RDP_BRIDGE_BAD_ARG;
    }
    let host = match unsafe { c_str_to_owned(target_host) } {
        Some(v) => v,
        None => return RDP_BRIDGE_BAD_ARG,
    };
    let username = match unsafe { c_str_to_owned(username) } {
        Some(v) => v,
        None => return RDP_BRIDGE_BAD_ARG,
    };
    let password = match unsafe { c_str_to_owned(password) } {
        Some(v) => v,
        None => return RDP_BRIDGE_BAD_ARG,
    };

    use std::os::unix::io::FromRawFd;
    let client_tcp = unsafe { StdTcpStream::from_raw_fd(client_fd) };

    match spawn_session(client_tcp, host, target_port, username, password) {
        Ok(id) => {
            unsafe { *out_handle = id };
            RDP_BRIDGE_OK
        }
        Err(e) => {
            error!(error = ?e, "rdp_bridge_start_unix_fd: failed to spawn session");
            RDP_BRIDGE_RUNTIME_ERROR
        }
    }
}

/// # Safety
///
/// See `rdp_bridge_start_unix_fd`.
#[cfg(windows)]
#[no_mangle]
pub unsafe extern "C" fn rdp_bridge_start_windows_socket(
    client_socket: usize,
    target_host: *const c_char,
    target_port: u16,
    username: *const c_char,
    password: *const c_char,
    out_handle: *mut u64,
) -> i32 {
    if out_handle.is_null() {
        return RDP_BRIDGE_BAD_ARG;
    }
    let host = match unsafe { c_str_to_owned(target_host) } {
        Some(v) => v,
        None => return RDP_BRIDGE_BAD_ARG,
    };
    let username = match unsafe { c_str_to_owned(username) } {
        Some(v) => v,
        None => return RDP_BRIDGE_BAD_ARG,
    };
    let password = match unsafe { c_str_to_owned(password) } {
        Some(v) => v,
        None => return RDP_BRIDGE_BAD_ARG,
    };

    use std::os::windows::io::{FromRawSocket, RawSocket};
    let client_tcp = unsafe { StdTcpStream::from_raw_socket(client_socket as RawSocket) };

    match spawn_session(client_tcp, host, target_port, username, password) {
        Ok(id) => {
            unsafe { *out_handle = id };
            RDP_BRIDGE_OK
        }
        Err(e) => {
            error!(error = ?e, "rdp_bridge_start_windows_socket: failed to spawn session");
            RDP_BRIDGE_RUNTIME_ERROR
        }
    }
}

#[no_mangle]
pub extern "C" fn rdp_bridge_wait(handle: u64) -> i32 {
    let join = {
        let handles = HANDLES.lock().expect("HANDLES poisoned");
        match handles.get(&handle) {
            Some(entry) => entry.join.lock().expect("join poisoned").take(),
            None => return RDP_BRIDGE_INVALID_HANDLE,
        }
    };

    match join {
        Some(jh) => match jh.join() {
            Ok(Ok(())) => {
                info!(handle, "rdp_bridge_wait: session ended cleanly");
                RDP_BRIDGE_OK
            }
            Ok(Err(e)) => {
                error!(handle, error = ?e, "rdp_bridge_wait: session failed");
                RDP_BRIDGE_SESSION_ERROR
            }
            Err(_) => {
                error!(handle, "rdp_bridge_wait: session thread panicked");
                RDP_BRIDGE_THREAD_PANIC
            }
        },
        None => RDP_BRIDGE_OK,
    }
}

#[no_mangle]
pub extern "C" fn rdp_bridge_cancel(handle: u64) -> i32 {
    let handles = HANDLES.lock().expect("HANDLES poisoned");
    match handles.get(&handle) {
        Some(entry) => {
            entry.cancel.cancel();
            RDP_BRIDGE_OK
        }
        None => RDP_BRIDGE_INVALID_HANDLE,
    }
}

#[no_mangle]
pub extern "C" fn rdp_bridge_free(handle: u64) -> i32 {
    let mut handles = HANDLES.lock().expect("HANDLES poisoned");
    if handles.remove(&handle).is_some() {
        RDP_BRIDGE_OK
    } else {
        RDP_BRIDGE_INVALID_HANDLE
    }
}

/// Poll the next event, blocking up to `timeout_ms` ms. On RDP_POLL_OK,
/// caller owns *payload_ptr (must libc::free).
///
/// # Safety
///
/// `out` must be a non-null, writable `*mut RdpEvent`.
#[no_mangle]
pub unsafe extern "C" fn rdp_bridge_poll_event(
    handle: u64,
    out: *mut RdpEvent,
    timeout_ms: u32,
) -> i32 {
    if out.is_null() {
        return RDP_POLL_INVALID_HANDLE;
    }

    // Avoid holding the HANDLES lock across the await.
    let take_result: Result<Option<mpsc::UnboundedReceiver<SessionEvent>>, i32> = {
        let handles = HANDLES.lock().expect("HANDLES poisoned");
        match handles.get(&handle) {
            None => Err(RDP_POLL_INVALID_HANDLE),
            Some(entry) => {
                if *entry.events_ended.lock().expect("events_ended poisoned") {
                    Err(RDP_POLL_ENDED)
                } else {
                    Ok(entry.events_rx.lock().expect("events_rx poisoned").take())
                }
            }
        }
    };
    let mut rx = match take_result {
        Ok(Some(rx)) => rx,
        // Concurrent poll on the same handle; callers must serialize.
        Ok(None) => return RDP_POLL_INVALID_HANDLE,
        Err(code) => return code,
    };

    // Short-lived single-thread runtime just for the timeout. Cheap; the
    // bridge thread runs its own runtime.
    let result = {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("build poll runtime");
        rt.block_on(async {
            tokio::time::timeout(Duration::from_millis(timeout_ms.into()), rx.recv()).await
        })
    };

    let outcome = match result {
        Ok(Some(event)) => {
            let rdp_event = RdpEvent::from_session_event(event);
            unsafe { out.write(rdp_event) };
            RDP_POLL_OK
        }
        Ok(None) => RDP_POLL_ENDED, // sender side dropped (bridge ended)
        Err(_timeout) => RDP_POLL_TIMEOUT,
    };

    // Restore the receiver, or mark ended if the channel reported closed.
    let handles = HANDLES.lock().expect("HANDLES poisoned");
    if let Some(entry) = handles.get(&handle) {
        if outcome == RDP_POLL_ENDED {
            *entry.events_ended.lock().expect("events_ended poisoned") = true;
        } else {
            *entry.events_rx.lock().expect("events_rx poisoned") = Some(rx);
        }
    }

    outcome
}
