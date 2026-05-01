# Infisical RDP Bridge

Rust static library that provides the RDP MITM bridge for Infisical PAM Windows/RDP support. Uses [IronRDP](https://github.com/Devolutions/IronRDP) for protocol handling.

## Prerequisites

- Rust 1.95.0 (automatically selected via `rust-toolchain.toml`)
- For cross-compilation: [cross](https://github.com/cross-rs/cross)

```bash
# Install Rust if not already installed
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# The rust-toolchain.toml will auto-install 1.95.0 on first build,
# or install manually:
rustup install 1.95.0
```

## Building

### Local development (macOS/Linux)

```bash
cd packages/pam/handlers/rdp/native
cargo build --release
```

The static library is output to `target/release/libinfisical_rdp_bridge.a`.

### Cross-compilation

For Linux targets from any host:

```bash
cargo install cross --locked --version 0.2.5
cross build --release --target x86_64-unknown-linux-gnu
```

Supported targets:
- `x86_64-unknown-linux-gnu`
- `aarch64-unknown-linux-gnu`
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`
- `x86_64-pc-windows-gnu`

## Building the CLI with RDP support

The Go CLI links against the static library via CGO. Build with the `rdp` tag:

```bash
cd /path/to/cli
go build -tags rdp -o infisical ./cmd/infisical
```

Without `-tags rdp`, the CLI uses a stub that returns `ErrRdpUnavailable` for all RDP operations.

## Verifying the build

```bash
./infisical pam rdp --help
```

If you see help output, the bridge linked correctly. If you see "rdp bridge: not available in this build", the stub is active (missing `-tags rdp` or missing static library).

## Architecture

- `src/lib.rs` - Crate entry point, re-exports
- `src/ffi.rs` - C ABI exports (see `include/rdp_bridge.h`)
- `src/bridge.rs` - MITM logic: accepts client connection, injects credentials, connects to target
- `src/config.rs` - TLS and connection configuration

The bridge runs async Tokio tasks but exposes a blocking C ABI. The Go side calls `rdp_bridge_start_*` to spawn the session, `rdp_bridge_wait` to block until completion, and `rdp_bridge_free` to release resources.
