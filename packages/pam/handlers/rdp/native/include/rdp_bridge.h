/* C ABI; see ffi.rs. Lifecycle: start_* -> wait -> free. start_* takes
 * ownership of the client fd/socket. cancel is thread-safe. */

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

/* Poll return codes (distinct number space from the bridge status codes
 * above; consumed by rdp_bridge_poll_event only). */
#define RDP_POLL_OK                   0
#define RDP_POLL_TIMEOUT              1
#define RDP_POLL_ENDED                2
#define RDP_POLL_INVALID_HANDLE      -1

/* Event type discriminator. */
#define RDP_EVENT_KEYBOARD            1
#define RDP_EVENT_UNICODE             2
#define RDP_EVENT_MOUSE               3
#define RDP_EVENT_TARGET_FRAME        4

/* Fields reused across variants; check event_type. For TargetFrame,
 * payload_ptr is libc-malloc'd and the Go caller must C.free it. */
struct RdpEvent {
    uint8_t   event_type;
    uint64_t  elapsed_ns;
    uint32_t  value_a;
    uint32_t  value_b;
    uint32_t  flags;
    int32_t   wheel_delta;
    uint8_t   action;
    uint8_t  *payload_ptr;
    uint32_t  payload_len;
};

int32_t rdp_bridge_poll_event(uint64_t handle, struct RdpEvent *out, uint32_t timeout_ms);

#ifdef __cplusplus
}
#endif

#endif
