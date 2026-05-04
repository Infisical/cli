//! C ABI for the bridge. Called from Go via CGo.
//!
//! Each session runs on its own OS thread with a current-thread tokio
//! runtime. `start_*` transfers ownership of the client fd/socket to
//! Rust (Go hands in a dup). Contract: wait, then free.

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
    // Taken by wait(); None afterward.
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
    acceptor_username: String,
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
                    acceptor_username,
                };
                run_mitm(client, endpoint, cancel_for_thread).await
            })
        })?;

    Ok(register(BridgeEntry {
        cancel,
        join: Mutex::new(Some(join)),
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
    acceptor_username: *const c_char,
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
    let acceptor_username = match unsafe { c_str_to_owned(acceptor_username) } {
        Some(v) => v,
        None => return RDP_BRIDGE_BAD_ARG,
    };

    use std::os::unix::io::FromRawFd;
    let client_tcp = unsafe { StdTcpStream::from_raw_fd(client_fd) };

    match spawn_session(
        client_tcp,
        host,
        target_port,
        username,
        password,
        acceptor_username,
    ) {
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
    acceptor_username: *const c_char,
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
    let acceptor_username = match unsafe { c_str_to_owned(acceptor_username) } {
        Some(v) => v,
        None => return RDP_BRIDGE_BAD_ARG,
    };

    use std::os::windows::io::{FromRawSocket, RawSocket};
    let client_tcp = unsafe { StdTcpStream::from_raw_socket(client_socket as RawSocket) };

    match spawn_session(
        client_tcp,
        host,
        target_port,
        username,
        password,
        acceptor_username,
    ) {
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
