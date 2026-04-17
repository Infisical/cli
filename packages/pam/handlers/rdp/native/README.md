# infisical-rdp-bridge (Phase 0 spike)

Standalone Rust binary proving the IronRDP acceptor + connector MITM bridge works
with credential injection against a real Windows target.

**Status**: Phase 0 scaffolding. Not wired into the gateway yet. Not FFI-shaped yet.

## What this proves

- `ironrdp-acceptor` can terminate an inbound RDP connection from `mstsc`,
  `xfreerdp`, or `ironrdp-web`.
- `ironrdp-connector` can open an outbound RDP connection to a Windows target
  with vaulted `{username, password}` injected via CredSSP.
- Bytes flow correctly between the two halves after both reach the active phase.

## What this does NOT prove

- Event tap / recording (Phase 1)
- FFI boundary to Go (Phase 1)
- Gateway integration (Phase 2)
- Browser playback (Phase 5)

## Run

```
cargo run --release -- \
  --listen 127.0.0.1:3389 \
  --target <windows-host>:3389 \
  --username <local-user> \
  --password <password>
```

Then point a client at the listen address:

```
xfreerdp /v:127.0.0.1 /cert:ignore
# or
mstsc /v:127.0.0.1
```

The session should open directly on the Windows target without a credential
prompt, because the bridge injected credentials on the outbound leg.

## Exit gate for Phase 0

All three of `xfreerdp`, `mstsc`, and `ironrdp-web` connect through the bridge
and land on a logged-in Windows desktop without being prompted for credentials.

## Not for production

- Credentials passed on the command line (visible in process listings)
- Self-signed TLS cert generated at startup, no validation of target cert
- No event tap, no recording, no error taxonomy
- Single-session — no concurrent client handling
- Panics on most errors instead of recovering
