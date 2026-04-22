/*
 * infisical-rdp-bridge C ABI
 *
 * C-callable interface to the Rust MITM bridge. Consumed via CGo from the
 * Go gateway and CLI code. All functions are thread-safe unless noted.
 *
 * Session lifecycle:
 *   1. Caller hands in a connected TCP file descriptor / socket and target
 *      credentials to `rdp_bridge_start_*`. On success, the call returns
 *      immediately with an opaque `uint64_t` handle; the bridge runs on a
 *      dedicated OS thread.
 *   2. `rdp_bridge_wait(handle)` blocks until the session ends.
 *   3. `rdp_bridge_cancel(handle)` can be called at any time from any
 *      thread to signal the session to abort. Idempotent.
 *   4. `rdp_bridge_free(handle)` releases the registry entry. Call after
 *      `wait` returns.
 *
 * Ownership of the client fd / socket transfers to the bridge on a
 * successful `start_*` call. The bridge closes it when the session ends.
 * Callers that need to keep their own reference should dup before calling
 * (syscall.Dup on Unix, WSADuplicateSocket or equivalent on Windows).
 */

#ifndef INFISICAL_RDP_BRIDGE_H
#define INFISICAL_RDP_BRIDGE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Status codes returned by all functions. */
#define RDP_BRIDGE_OK                 0
#define RDP_BRIDGE_SESSION_ERROR      1
#define RDP_BRIDGE_THREAD_PANIC       2
#define RDP_BRIDGE_INVALID_HANDLE    -1
#define RDP_BRIDGE_BAD_ARG           -2
#define RDP_BRIDGE_RUNTIME_ERROR     -3

#if defined(__unix__) || defined(__APPLE__)
/*
 * Start a session consuming a Unix client file descriptor.
 *
 *   client_fd      — connected TCP socket; ownership transfers to the bridge.
 *   target_host    — NUL-terminated UTF-8 hostname or IP.
 *   target_port    — RDP port (usually 3389).
 *   username       — NUL-terminated UTF-8 username to inject via CredSSP.
 *   password       — NUL-terminated UTF-8 password.
 *   out_handle     — written with the session handle on success.
 *
 * Returns RDP_BRIDGE_OK on success, RDP_BRIDGE_BAD_ARG for invalid
 * arguments, RDP_BRIDGE_RUNTIME_ERROR if the session thread could not
 * be started.
 */
int32_t rdp_bridge_start_unix_fd(
    int          client_fd,
    const char  *target_host,
    uint16_t     target_port,
    const char  *username,
    const char  *password,
    uint64_t    *out_handle
);
#endif /* unix */

#if defined(_WIN32) || defined(_WIN64)
/*
 * Start a session consuming a Windows SOCKET handle (passed as uintptr_t
 * so the ABI is fixed regardless of whether the caller uses SOCKET or
 * HANDLE). Same semantics as `rdp_bridge_start_unix_fd`.
 */
int32_t rdp_bridge_start_windows_socket(
    uintptr_t    client_socket,
    const char  *target_host,
    uint16_t     target_port,
    const char  *username,
    const char  *password,
    uint64_t    *out_handle
);
#endif /* windows */

/*
 * Block until the session on `handle` ends. Returns RDP_BRIDGE_OK on
 * clean end, RDP_BRIDGE_SESSION_ERROR on handshake / forwarding error,
 * RDP_BRIDGE_THREAD_PANIC if the session thread panicked,
 * RDP_BRIDGE_INVALID_HANDLE if the handle is unknown. Calling a second
 * time on the same handle returns RDP_BRIDGE_OK.
 */
int32_t rdp_bridge_wait(uint64_t handle);

/*
 * Signal the session to cancel. The session's tokio task is aborted at
 * the next await point and `wait` will then return. Idempotent; safe
 * from any thread. Returns RDP_BRIDGE_OK or RDP_BRIDGE_INVALID_HANDLE.
 */
int32_t rdp_bridge_cancel(uint64_t handle);

/*
 * Release the handle's registry entry. Must be called after `wait` has
 * returned. Returns RDP_BRIDGE_OK or RDP_BRIDGE_INVALID_HANDLE.
 */
int32_t rdp_bridge_free(uint64_t handle);

#ifdef __cplusplus
}
#endif

#endif /* INFISICAL_RDP_BRIDGE_H */
