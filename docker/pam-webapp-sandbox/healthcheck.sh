#!/usr/bin/env bash
#
# Readiness probe: is the RDP server listening on $RDP_PORT?
#
# We check the listening socket PASSIVELY via /proc/net/tcp rather than opening a
# real TCP connection — a bare connect makes freerdp-shadow log a transport error
# ("BIO_read ... ERRCONNECT_CONNECT_TRANSPORT_FAILED") on every probe, which would
# spam the Gateway's logs for the whole session.
#
# A LISTEN socket appears in /proc/net/tcp with state 0A and an all-zero remote
# address; the local port is the 4-digit uppercase hex of $RDP_PORT.
set -u

port_hex=$(printf '%04X' "${RDP_PORT:-3389}")

grep -qiE ":${port_hex} [0-9A-F]+:0000 0A " /proc/net/tcp /proc/net/tcp6 2>/dev/null
