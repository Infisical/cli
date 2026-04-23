/*
 * infisical-rdp-bridge C ABI. See ffi.rs for details. Lifecycle:
 *   start_* -> wait -> free; cancel may be called from any thread.
 * start_* transfers ownership of the client fd/socket to the bridge.
 */

#ifndef INFISICAL_RDP_BRIDGE_H
#define INFISICAL_RDP_BRIDGE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RDP_BRIDGE_OK                 0
#define RDP_BRIDGE_SESSION_ERROR      1
#define RDP_BRIDGE_THREAD_PANIC       2
#define RDP_BRIDGE_INVALID_HANDLE    -1
#define RDP_BRIDGE_BAD_ARG           -2
#define RDP_BRIDGE_RUNTIME_ERROR     -3

#if defined(__unix__) || defined(__APPLE__)
int32_t rdp_bridge_start_unix_fd(
    int          client_fd,
    const char  *target_host,
    uint16_t     target_port,
    const char  *username,
    const char  *password,
    uint64_t    *out_handle
);
#endif

#if defined(_WIN32) || defined(_WIN64)
int32_t rdp_bridge_start_windows_socket(
    uintptr_t    client_socket,
    const char  *target_host,
    uint16_t     target_port,
    const char  *username,
    const char  *password,
    uint64_t    *out_handle
);
#endif

int32_t rdp_bridge_wait(uint64_t handle);
int32_t rdp_bridge_cancel(uint64_t handle);
int32_t rdp_bridge_free(uint64_t handle);

#ifdef __cplusplus
}
#endif

#endif
