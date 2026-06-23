# PAM webapp sandbox image

The per-session, server-side browser for the PAM **`webapp`** resource type. The
Gateway launches one container per web-access session (M3), navigated to the
resource's `TARGET_URL`, and the existing RDP MITM bridge connects to the
container's local RDP server and streams the browser into the user's tab — no
VPN, no client install, fully recorded/replayable.

This directory is the standalone image (milestone **M1**). It does not depend on
any Gateway wiring; you can build and exercise it with a raw RDP client.

## Stack

```
TARGET_URL ─► chromium --kiosk ─► Xvfb :0 ──XDamage──► freerdp-shadow-cli ──RDP/TLS──► client
                                       ▲                      │
                                       └────── XTEST ◄────────┘  (mouse/keyboard)
```

- **RDP server: `freerdp-shadow-cli`** (from `freerdp2-shadow-x11`), mirroring an
  Xvfb display via XDamage and injecting input via XTEST. This is the server the
  M0 spike proved compatible with the bridge — see
  [`docs/completed/m0.md`](../../../docs/completed/m0.md). We kept it deliberately
  rather than re-evaluating (e.g. weston's RDP backend) in isolation.
- **Security: TLS, no NLA** (`/sec:tls`). The bridge's connector requests
  `SSL|HYBRID|HYBRID_EX` and settles on plain `SSL` (no CredSSP), so the server
  needs no NLA and injects no credentials.

## Build

```bash
docker build -t infisical-pam-webapp-sandbox:dev cli/docker/pam-webapp-sandbox/
```

On Apple Silicon this builds a native `linux/arm64` image. Release builds the
multi-arch (`linux/amd64,linux/arm64`) published image.

## Run

```bash
docker run --rm \
  -e TARGET_URL=https://example.com \
  -p 127.0.0.1:3389:3389 \
  --name webapp-sandbox \
  infisical-pam-webapp-sandbox:dev
```

(`tini` is already the image's entrypoint, so don't add `docker run --init` — it
double-stacks a second init and prints a "Tini is not running as PID 1" warning.)

| env | default | meaning |
|--------------------|------------------|---------------------------------------|
| `TARGET_URL`       | `about:blank`    | page the browser opens on launch      |
| `SCREEN_GEOMETRY`  | `1920x1080x24`   | Xvfb geometry; browser sizes to match |
| `RDP_PORT`         | `3389`           | port the RDP server listens on        |

Readiness: the image has a `HEALTHCHECK` on the RDP port, so `docker ps` shows
`(healthy)` once the server is up (the Gateway waits on this in M3).

## Manual verification (M1)

Connect a raw RDP client **using the same security settings the Gateway bridge
uses** (TLS, no NLA) so "works in my client" can't diverge from "works through
the bridge". `/sec:tls` forces TLS-only, which *is* NLA-disabled in FreeRDP 3 (the
old standalone `-sec-nla` toggle is gone — passing it errors with "Unexpected
keyword").

```bash
# macOS: use the SDL client (renders in a native window; no X server needed).
sdl-freerdp /v:127.0.0.1:3389 /sec:tls /cert:ignore /u:infisical /p:infisical /size:1920x1080

# Linux (or macOS with XQuartz running + $DISPLAY set): the X11 client works too.
xfreerdp /v:127.0.0.1:3389 /sec:tls /cert:ignore /u:infisical /p:infisical /size:1920x1080
```

Expected: `example.com` renders and is interactive — clicks, typing into inputs,
native `<select>` dropdowns and dialogs all work.

Notes:
- The connecting username must be **`infisical`** (the account that exists in the
  image; the webapp synthetic account in M2 uses the same name). The password is
  ignored (PAM is permissive — see below); the `/p is insecure` warning is benign.
- On macOS, `xfreerdp` (the X11 build) needs XQuartz running and `$DISPLAY` set or
  it fails with "failed to open display"; `sdl-freerdp` avoids that. The
  "Microsoft Remote Desktop" client defaults to NLA and can't easily disable it,
  so it won't connect to this no-NLA server — use a FreeRDP client.

## Notes / deferred work

- **PAM:** `freerdp-shadow`'s X11 backend PAM-authenticates the connecting user
  even with RDP-level auth off, so the image ships a permissive PAM policy for
  the shadow services only (not the global `common-*` stacks). There is no real
  interactive login surface here.
- **Hardening (M6):** seccomp, dropped capabilities, restoring the browser
  sandbox, and the network egress lock are intentionally out of scope for M1.
  The container already runs as the unprivileged `infisical` user.
- **Lifecycle (M3):** `tini` is PID 1, so the Gateway's `SIGTERM` shuts the
  container down cleanly; if Xvfb / chromium / the RDP server dies, the entrypoint
  exits and the container stops, letting the Gateway detect and tear down.
