#ifndef INFISICAL_RDP_BRIDGE_H
#define INFISICAL_RDP_BRIDGE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Poll return codes ---- */

#define RDP_POLL_OK              0
#define RDP_POLL_TIMEOUT         1
#define RDP_POLL_ENDED           2
#define RDP_POLL_INVALID_HANDLE (-1)

/* ---- Event types ---- */

#define RDP_EVT_KEYBOARD      1
#define RDP_EVT_UNICODE       2
#define RDP_EVT_MOUSE         3
#define RDP_EVT_TARGET_FRAME  4

/* TargetFrame.action values */
#define RDP_ACTION_X224       0
#define RDP_ACTION_FASTPATH   1

/* C-ABI event. event_type discriminates which fields are meaningful.
 *
 *   Keyboard:      value_a = scancode, flags = KeyboardFlags bits
 *   Unicode:       value_a = code_point, flags = KeyboardFlags bits
 *   Mouse:         value_a = x, value_b = y, flags = PointerFlags bits,
 *                  wheel_delta = signed wheel units
 *   TargetFrame:   value_a = payload bytes, action = X224 or FASTPATH
 *
 * elapsed_ns is nanoseconds since the bridge started its background task.
 */
typedef struct {
    uint8_t  event_type;
    uint64_t elapsed_ns;
    uint32_t value_a;
    uint32_t value_b;
    uint32_t flags;
    int32_t  wheel_delta;
    uint8_t  action;
} rdp_event_t;

/* Start a new bridge session. The bridge listens on `listen_addr` and
 * will accept exactly ONE inbound connection, then proxy it to
 * target_host:target_port injecting the provided credentials.
 *
 * All strings must be null-terminated UTF-8.
 *
 * Returns a non-zero handle on success; returns 0 on argument errors.
 * The bridge runs in a background thread; it does not block this call.
 */
uint64_t rdp_bridge_start(
    const char *target_host,
    uint16_t target_port,
    const char *username,
    const char *password,
    const char *listen_addr
);

/* Poll the next session event, blocking up to `timeout_ms`.
 *
 * Return codes:
 *   RDP_POLL_OK              event written to *out
 *   RDP_POLL_TIMEOUT         no event within timeout; *out unchanged
 *   RDP_POLL_ENDED           session ended; no further events
 *   RDP_POLL_INVALID_HANDLE  unknown or closed handle
 */
int32_t rdp_bridge_poll_event(uint64_t handle, rdp_event_t *out, uint32_t timeout_ms);

/* Close a bridge and release its resources. Returns 0 on success,
 * RDP_POLL_INVALID_HANDLE if the handle is unknown.
 */
int32_t rdp_bridge_close(uint64_t handle);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* INFISICAL_RDP_BRIDGE_H */
