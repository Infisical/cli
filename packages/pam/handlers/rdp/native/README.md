# infisical-rdp-bridge

Rust crate that implements the RDP MITM bridge for Infisical's PAM Windows
handler. The bridge terminates an inbound RDP connection from a native
client (Windows App, mstsc, xfreerdp, sdl-freerdp), opens an outbound
connection to a Windows target, injects credentials at CredSSP on the
target side, and then byte-forwards raw TLS traffic in both directions.

## Architecture

**Post-CredSSP passthrough.** The bridge drives each half of the
connection only far enough to complete credential injection:

1. Inbound (acceptor): X.224 negotiation → TLS upgrade with a self-signed
   cert → CredSSP/NLA with the fixed placeholder credential
   `infisical`/`infisical`.
2. Outbound (connector): X.224 negotiation → TLS upgrade → CredSSP/NLA
   with the real target credentials injected via sspi's NTLM.
3. Both halves run concurrently via `tokio::try_join!` so the client
   doesn't sit waiting after its CredSSP completes.
4. After both CredSSP sequences finish, we drop the acceptor / connector
   state machines and use `tokio::io::copy_bidirectional` on the raw TLS
   streams.

From this point, client and target negotiate MCS, channels, capabilities,
and share state **directly with each other through us**. We never
synthesize our own Connect Initial / Connect Response, so we avoid the
capability-drift and identifier-drift that naive acceptor+connector
handshake forwarding introduces. Strict clients (Windows App, mstsc)
that validate echoes like `ServerCoreData.clientRequestedProtocols`
accept the session because target's response reflects the values
**client** sent, not what our connector would have advertised.

## Scope

No event tap, no session recording. The crate compiles to both a
`staticlib` (consumed via CGo from the Go wrapper at
`packages/pam/handlers/rdp/`, see [Go wrapper](#go-wrapper) below) and
an `rlib` (for the in-tree test binary).

## Build

```sh
cargo build --release
```

## Manual validation

Start the bridge pointing at a real Windows server:

```sh
RUST_LOG=info cargo run --release -- \
    --listen 127.0.0.1:3390 \
    --target-host <windows-ip-or-hostname> \
    --target-port 3389 \
    --username <real-user> \
    --password <real-pass>
```

Then connect any native RDP client to `127.0.0.1:3390` with credentials
`infisical` / `infisical`. Examples:

**Microsoft Windows App (macOS):** Add PC → `127.0.0.1:3390`, user
account `infisical` / `infisical`. Click through the self-signed cert
warning. This is the strict client and validates the full post-CredSSP
architecture end-to-end.

**sdl-freerdp (Linux/macOS):**

```sh
sdl-freerdp /v:127.0.0.1:3390 /u:infisical /p:infisical /cert:ignore
```

**mstsc (Windows):** Save a `.rdp` file with:

```
full address:s:127.0.0.1:3390
username:s:infisical
```

and supply `infisical` as the password when prompted.

### macOS dev note

On macOS, sspi's Kerberos DNS fallback via Bonjour adds ~4s of DNS
timeouts during CredSSP. Sessions still succeed (strict clients like
Windows App do not time out in that window), but CredSSP feels sluggish.
Production gateway deployments run on Linux, where `hickory-resolver`
returns NXDOMAIN in milliseconds, so this is a local-dev quirk only.

## Go wrapper

The static library in `target/release/libinfisical_rdp_bridge.a`
exports a C ABI (see [`include/rdp_bridge.h`](include/rdp_bridge.h))
that is consumed from the Go package at
`packages/pam/handlers/rdp/` via CGo. Build order:

```sh
# 1. Build the Rust static library first.
cd packages/pam/handlers/rdp/native && cargo build --release

# 2. Build the Go binary or package with the rdp tag.
cd - && go build -tags rdp ./packages/pam/handlers/rdp/cmd/bridge-test
```

Builds without `-tags rdp` (or on unsupported platforms) link against a
pure-Go stub that returns `ErrRdpUnavailable` from every constructor.

## Lints

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```
