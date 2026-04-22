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

## Phase 1 scope

Standalone test binary only. No FFI, no event tap, no session recording.
The crate compiles to both a `staticlib` (for later CGo linking) and an
`rlib` (for the in-tree test binary).

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
timeouts during CredSSP. This does not affect production gateway
deployments (Linux, where `hickory-resolver` returns NXDOMAIN in
milliseconds). If validating locally on macOS with strict clients,
prefer running the bridge inside a Linux container:

```sh
docker run --rm -v "$PWD":/work -v "$PWD/target-docker":/work/target \
    -w /work -p 127.0.0.1:3390:3390 rust:1-bookworm \
    bash -c "cargo build --release && \
        ./target/release/rdp-bridge-test \
        --listen 0.0.0.0:3390 \
        --target-host <windows-ip-or-hostname> \
        --username <user> --password '<pass>'"
```

The `target-docker` directory keeps the Linux build artifacts separate
from the host's macOS `target`.

## Lints

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```
