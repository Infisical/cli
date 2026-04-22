//! C ABI for the bridge. Designed to be called from Go via CGo.
//!
//! Model:
//!  - Each session runs on its own OS thread with a current-thread tokio
//!    runtime. Sessions are fully isolated.
//!  - `start_*` allocates an opaque `u64` handle, spawns the thread, and
//!    returns immediately. The handshake and passthrough happen inside
//!    the spawned thread.
//!  - `wait` blocks the calling thread until the session ends, returning
//!    0 on clean exit and 1 on session error.
//!  - `cancel` is idempotent: it signals the bridge's CancellationToken,
//!    which interrupts `run_mitm` at the next await point.
//!  - `free` removes the handle from the registry. Call after `wait`.
//!
//! Ownership of the client file descriptor / socket: Rust takes ownership
//! of what is passed in and closes it when the session ends. The Go
//! caller is expected to hand in a dup'd fd (syscall.Dup on Unix, the
//! Windows equivalent on Windows) so its own `net.Conn` lifetime stays
//! independent.

use std::collections::HashMap;
use std::ffi::{c_char, CStr};
use std::net::TcpStream as StdTcpStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};
use std::thread::JoinHandle;

use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use crate::bridge::{run_mitm, TargetEndpoint};

pub const RDP_BRIDGE_OK: i32 = 0;
pub const RDP_BRIDGE_SESSION_ERROR: i32 = 1;
pub const RDP_BRIDGE_THREAD_PANIC: i32 = 2;
pub const RDP_BRIDGE_INVALID_HANDLE: i32 = -1;
pub const RDP_BRIDGE_BAD_ARG: i32 = -2;
pub const RDP_BRIDGE_RUNTIME_ERROR: i32 = -3;

struct BridgeEntry {
    cancel: CancellationToken,
    /// Taken by `wait`; `None` afterward.
    join: Mutex<Option<JoinHandle<anyhow::Result<()>>>>,
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
/// `ptr` must be either null or a valid NUL-terminated C string with the
/// `'static` borrow of the caller's buffer lasting for the duration of
/// this call.
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
                run_mitm(client, endpoint, cancel_for_thread).await
            })
        })?;

    Ok(register(BridgeEntry {
        cancel,
        join: Mutex::new(Some(join)),
    }))
}

/// Start a new bridge session consuming a Unix client file descriptor.
///
/// # Safety
///
/// `client_fd` must be a valid open socket descriptor. Ownership transfers
/// to the bridge on success; the caller must not close it. On failure,
/// ownership stays with the caller. `target_host`, `username`, and
/// `password` must be NUL-terminated valid UTF-8 C strings. `out_handle`
/// must be a writable `uint64_t`.
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
    // Safety: contract states the caller transfers ownership of fd.
    let client_tcp = unsafe { StdTcpStream::from_raw_fd(client_fd) };

    match spawn_session(client_tcp, host, target_port, username, password) {
        Ok(id) => {
            // Safety: contract states out_handle is writable.
            unsafe { *out_handle = id };
            RDP_BRIDGE_OK
        }
        Err(e) => {
            error!(error = ?e, "rdp_bridge_start_unix_fd: failed to spawn session");
            RDP_BRIDGE_RUNTIME_ERROR
        }
    }
}

/// Start a new bridge session consuming a Windows SOCKET.
///
/// # Safety
///
/// `client_socket` must be a valid open `SOCKET`. Ownership transfers
/// to the bridge on success. See `rdp_bridge_start_unix_fd` for shared
/// string and out-param contracts.
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
    // Safety: contract states caller transfers ownership.
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

/// Block until the session on `handle` finishes.
///
/// Returns `RDP_BRIDGE_OK` on clean session end,
/// `RDP_BRIDGE_SESSION_ERROR` if the session ended with an error,
/// `RDP_BRIDGE_THREAD_PANIC` if the session thread panicked,
/// `RDP_BRIDGE_INVALID_HANDLE` if `handle` is unknown.
///
/// Safe to call from any thread. Calling a second time on the same handle
/// returns `RDP_BRIDGE_OK` (the session is already done).
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

/// Signal the session to cancel. Idempotent: safe to call multiple times.
/// After `cancel`, the caller should still `wait` to observe the session
/// actually finishing, and then `free` to release the handle.
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

/// Release the handle's resources. Must be called after `wait` has
/// returned. If the session thread is still running when `free` is
/// called, the handle is dropped and the thread becomes detached (still
/// owned by the registry entry; would leak). Callers should always pair
/// `wait` with `free`.
#[no_mangle]
pub extern "C" fn rdp_bridge_free(handle: u64) -> i32 {
    let mut handles = HANDLES.lock().expect("HANDLES poisoned");
    if handles.remove(&handle).is_some() {
        RDP_BRIDGE_OK
    } else {
        RDP_BRIDGE_INVALID_HANDLE
    }
}
