//! C ABI for Go consumers.
//!
//! Handle-based pattern: Rust owns all bridge state. Go receives opaque
//! u64 handles and passes them back on every call. Invalid handles fail
//! safely with error codes; there are no raw pointers across the FFI.
//!
//! Lifecycle:
//!   1. Go calls `rdp_bridge_start(target, user, pass, listen)` -> handle.
//!      The bridge begins listening in the background and returns
//!      immediately. It will accept ONE inbound connection and bridge it
//!      to the target.
//!   2. Go repeatedly calls `rdp_bridge_poll_event(handle, &out, timeout)`
//!      to drain structured events (keyboard, mouse, target frame).
//!   3. When the session ends (target closes, client closes, or error),
//!      `poll_event` returns `RDP_POLL_ENDED`.
//!   4. Go calls `rdp_bridge_close(handle)` to release resources.
//!
//! This is the minimal shape for Phase 1 Step 2. Later phases replace
//! "listen for one connection" with "accept an already-authenticated
//! socket from the gateway" by passing an OS file descriptor across the
//! boundary.

use std::collections::HashMap;
use std::ffi::{CStr, c_char};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use once_cell::sync::Lazy;
use tokio::sync::mpsc;
use tracing::{error, info};

use crate::bridge::{self, ProxyArgs};
use crate::events::SessionEvent;

// -- Poll return codes ---------------------------------------------------

/// An event was written to `*out`.
pub const RDP_POLL_OK: i32 = 0;
/// No event was available within the timeout. `*out` was not modified.
pub const RDP_POLL_TIMEOUT: i32 = 1;
/// The bridge has ended (target or client disconnected, or error).
/// No further events will arrive.
pub const RDP_POLL_ENDED: i32 = 2;
/// The handle is unknown or has been closed.
pub const RDP_POLL_INVALID_HANDLE: i32 = -1;

// -- Event types ---------------------------------------------------------

/// Discriminator for the C-ABI event struct.
#[repr(u8)]
pub enum RdpEventType {
    Keyboard = 1,
    Unicode = 2,
    Mouse = 3,
    TargetFrame = 4,
}

/// C-ABI friendly event. Fields are reused across variants; see
/// `event_type` to decide which fields are meaningful.
#[repr(C)]
pub struct RdpEvent {
    pub event_type: u8,
    /// Nanoseconds since bridge start.
    pub elapsed_ns: u64,
    /// Keyboard: scancode. Unicode: code point. Mouse: x. TargetFrame: bytes.
    pub value_a: u32,
    /// Mouse: y. Others: 0.
    pub value_b: u32,
    /// Keyboard/Mouse flags (raw bits from the RDP layer).
    pub flags: u32,
    /// Mouse wheel delta (signed). 0 for others.
    pub wheel_delta: i32,
    /// TargetFrame: 0 = X.224, 1 = FastPath. 0 for others.
    pub action: u8,
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
                bytes,
                elapsed_ns,
            } => Self {
                event_type: RdpEventType::TargetFrame as u8,
                elapsed_ns,
                value_a: bytes as u32,
                action: match action {
                    ironrdp_pdu::Action::X224 => 0,
                    ironrdp_pdu::Action::FastPath => 1,
                },
                ..Self::zero()
            },
        }
    }
}

// -- Handle table --------------------------------------------------------

struct BridgeHandle {
    events_rx: mpsc::UnboundedReceiver<SessionEvent>,
    /// Shutdown signal. Dropping this ends the background task.
    _shutdown: mpsc::UnboundedSender<()>,
    /// True once the events channel has been closed by the bridge.
    ended: bool,
}

static HANDLES: Lazy<Mutex<HashMap<u64, BridgeHandle>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);

// Dedicated thread + single-threaded runtime for each bridge session.
// Avoids the higher-ranked-lifetime Send issue with IronRDP's async state
// machines (they hold &dyn trait objects that aren't unconditionally Send).
// Thread-per-session is fine at POC scale; if we ever need 1000s of
// concurrent bridges per process we can revisit with a work-stealing
// runtime plus proper Send bounds upstream.

static TLS_INIT: Lazy<()> = Lazy::new(|| {
    let _ = rustls::crypto::ring::default_provider().install_default();
});

fn allocate_handle(handle: BridgeHandle) -> u64 {
    let id = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    HANDLES.lock().expect("handles lock").insert(id, handle);
    id
}


// -- Helpers -------------------------------------------------------------

/// Safe conversion from a C string pointer to an owned Rust String.
/// Returns None if the pointer is null or the string is not valid UTF-8.
unsafe fn c_str_to_owned(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .ok()
        .map(|s| s.to_owned())
}

// -- Public C ABI --------------------------------------------------------

/// Start a bridge session. The bridge begins listening on `listen_addr`
/// in the background and returns a handle immediately. It will accept
/// exactly one inbound client connection.
///
/// All string arguments must be null-terminated UTF-8.
///
/// Returns 0 on any argument parse failure; a valid handle is > 0.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rdp_bridge_start(
    target_host: *const c_char,
    target_port: u16,
    username: *const c_char,
    password: *const c_char,
    listen_addr: *const c_char,
) -> u64 {
    let _ = &*TLS_INIT;

    let Some(target_host) = (unsafe { c_str_to_owned(target_host) }) else {
        return 0;
    };
    let Some(username) = (unsafe { c_str_to_owned(username) }) else {
        return 0;
    };
    let Some(password) = (unsafe { c_str_to_owned(password) }) else {
        return 0;
    };
    let Some(listen_addr) = (unsafe { c_str_to_owned(listen_addr) }) else {
        return 0;
    };
    let Ok(listen) = listen_addr.parse::<std::net::SocketAddr>() else {
        return 0;
    };

    let args = ProxyArgs {
        listen,
        target: format!("{target_host}:{target_port}"),
        username,
        password,
    };

    // Wire the event channel: the bridge's background task will send
    // SessionEvents into this channel; Go drains them via poll_event.
    let (events_tx, events_rx) = mpsc::unbounded_channel();
    let (shutdown_tx, mut shutdown_rx) = mpsc::unbounded_channel::<()>();

    // Spawn a dedicated thread with its own current-thread tokio runtime.
    // Shutdown is coupled to dropping the _shutdown sender on the handle.
    std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(err) => {
                error!(?err, "failed to start bridge runtime");
                return;
            }
        };
        rt.block_on(async move {
            tokio::select! {
                result = bridge::run_single_with_events(args, events_tx) => {
                    if let Err(err) = result {
                        error!(?err, "bridge task failed");
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("bridge received shutdown signal");
                }
            }
        });
    });

    allocate_handle(BridgeHandle {
        events_rx,
        _shutdown: shutdown_tx,
        ended: false,
    })
}

/// Poll the next event, blocking up to `timeout_ms` milliseconds.
///
/// Returns:
///   * `RDP_POLL_OK` -- event written to *out
///   * `RDP_POLL_TIMEOUT` -- no event in time; *out not modified
///   * `RDP_POLL_ENDED` -- bridge finished; no more events
///   * `RDP_POLL_INVALID_HANDLE` -- unknown or already-closed handle
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rdp_bridge_poll_event(
    handle: u64,
    out: *mut RdpEvent,
    timeout_ms: u32,
) -> i32 {
    if out.is_null() {
        return RDP_POLL_INVALID_HANDLE;
    }

    // We take the receiver out for the duration of the poll so the lock
    // on HANDLES isn't held across an await. Put it back when done.
    let mut rx = match {
        let mut handles = HANDLES.lock().expect("handles lock");
        let h = match handles.get_mut(&handle) {
            Some(h) => h,
            None => return RDP_POLL_INVALID_HANDLE,
        };
        if h.ended {
            return RDP_POLL_ENDED;
        }
        // Temporarily replace the receiver with a dummy so we can own it.
        let (_dummy_tx, dummy_rx) = mpsc::unbounded_channel();
        std::mem::replace(&mut h.events_rx, dummy_rx)
    } {
        rx => rx,
    };

    // Poll on a lightweight one-off runtime. Using a short-lived runtime
    // here avoids sharing one with the bridge threads (which own their
    // own runtimes). The overhead per poll is a few microseconds.
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
        Ok(None) => {
            // Channel closed by the bridge task -- session ended.
            RDP_POLL_ENDED
        }
        Err(_timeout) => RDP_POLL_TIMEOUT,
    };

    // Put the receiver back (or mark ended).
    {
        let mut handles = HANDLES.lock().expect("handles lock");
        if let Some(h) = handles.get_mut(&handle) {
            if outcome == RDP_POLL_ENDED {
                h.ended = true;
            } else {
                h.events_rx = rx;
            }
        }
    }

    outcome
}

/// Tear down the bridge and free resources.
/// Safe to call multiple times; returns 0 for unknown handles.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rdp_bridge_close(handle: u64) -> i32 {
    let mut handles = HANDLES.lock().expect("handles lock");
    if handles.remove(&handle).is_some() {
        // Dropping the handle drops the shutdown sender, which signals
        // the background task to exit.
        0
    } else {
        RDP_POLL_INVALID_HANDLE
    }
}
