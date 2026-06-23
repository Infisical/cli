#!/usr/bin/env bash
#
# Infisical PAM webapp sandbox entrypoint.
#
# Brings up a virtual X display, a headful browser navigated to TARGET_URL, and a
# local RDP server (freerdp-shadow-cli) that mirrors the display and injects input
# via XTEST. The RDP MITM bridge on the Gateway connects to this server and streams
# the browser into the user's tab.
#
# RDP security: /sec:tls forces TLS with NO NLA. The bridge's connector requests
# SSL|HYBRID|HYBRID_EX and settles on plain SSL (no CredSSP), so no credentials are
# injected. Connect a raw client the same way: `/sec:tls -sec-nla`.
#
# Supervision: if Xvfb, chromium, or the RDP server exits, the whole container
# exits so the Gateway can detect the failure and tear the session down (M3).
set -euo pipefail

GEOM="${SCREEN_GEOMETRY:-1920x1080x24}"
URL="${TARGET_URL:-about:blank}"
RDP_PORT="${RDP_PORT:-3389}"

# Derive the browser window size from the X geometry (1920x1080x24 -> 1920 1080).
RES="${GEOM%x*}"
WIDTH="${RES%x*}"
HEIGHT="${RES#*x}"

export DISPLAY=:0
export HOME="${HOME:-/home/infisical}"

log() { echo "[webapp-sandbox] $*"; }

pids=()
cleaned=0
cleanup() {
  [ "$cleaned" = 1 ] && return 0
  cleaned=1
  log "shutting down"
  for pid in "${pids[@]:-}"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
}
trap 'cleanup; exit 143' TERM INT
trap cleanup EXIT

log "starting Xvfb ($GEOM) on $DISPLAY"
Xvfb :0 -screen 0 "$GEOM" -ac \
  +extension RANDR +extension XTEST +extension DAMAGE \
  -nolisten tcp &
xvfb_pid=$!
pids+=("$xvfb_pid")

# Wait for the X server to accept connections before starting clients.
for _ in $(seq 1 100); do
  xdpyinfo >/dev/null 2>&1 && break
  sleep 0.1
done
xdpyinfo >/dev/null 2>&1 || { log "FATAL: Xvfb did not come up"; exit 1; }
log "Xvfb ready"

# Minimal window manager so the browser window is mapped and sized.
openbox &
pids+=("$!")

log "launching chromium -> $URL (${WIDTH}x${HEIGHT})"
# --no-sandbox: the browser's own sandbox needs user namespaces / caps; restoring
#   it (or relying on the container sandbox instead) is M6's job.
chromium \
  --no-sandbox \
  --disable-gpu \
  --disable-dev-shm-usage \
  --disable-software-rasterizer \
  --no-first-run \
  --no-default-browser-check \
  --disable-infobars \
  --disable-session-crashed-bubble \
  --disable-features=Translate \
  --force-device-scale-factor=1 \
  --user-data-dir=/tmp/chromium-profile \
  --window-position=0,0 \
  --window-size="${WIDTH},${HEIGHT}" \
  --kiosk \
  "$URL" >/tmp/chromium.log 2>&1 &
chromium_pid=$!
pids+=("$chromium_pid")

# Local RDP server mirroring :0. Self-signed cert auto-generated under
# $HOME/.config/freerdp/shadow/ (clients connect with /cert:ignore).
log "starting freerdp-shadow-cli on :$RDP_PORT (sec:tls, no NLA)"
freerdp-shadow-cli "/port:$RDP_PORT" /bind-address:0.0.0.0 /sec:tls &
shadow_pid=$!
pids+=("$shadow_pid")

log "all processes up; supervising (xvfb=$xvfb_pid chromium=$chromium_pid shadow=$shadow_pid)"

# Exit as soon as any critical process dies.
set +e
wait -n "$xvfb_pid" "$chromium_pid" "$shadow_pid"
code=$?
set -e
log "a critical process exited (code $code); stopping container"
exit "$code"
