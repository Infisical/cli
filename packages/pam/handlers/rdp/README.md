# PAM handler: Windows / RDP

Go CGo wrapper over the native Rust RDP bridge in `native/`.

The handler lives here; the protocol work is in `native/`.

## Build

The Rust static library must exist before `go build` can link this package:

```
go generate ./packages/pam/handlers/rdp/...
```

That runs `cargo build --release` inside `native/` and produces
`native/target/release/libinfisical_rdp_bridge.a`, which CGo picks up
automatically.

For a clean rebuild:

```
(cd packages/pam/handlers/rdp/native && cargo clean) && \
  go generate ./packages/pam/handlers/rdp/...
```

## Requirements

- Rust toolchain (stable, 1.89+). Install via rustup.
- The standard system toolchain CGo already uses (clang on macOS, gcc on Linux).

## What this handler does

- Consumes a `net.Conn` handed in by `pam.HandlePAMProxy`.
- Dups the socket fd and passes it to the native bridge via `StartWithConn`.
- Polls structured events (keyboard, mouse, target frames) and writes each
  one as a JSON-encoded `TerminalEvent` with `TerminalChannelRDP` into the
  session log.

## Standalone spike binary

The Rust crate also produces a binary useful for manual testing without
the gateway. See `native/README.md` for its usage.

## Platform support

Unix only for Phase 1/2 POC. Windows gateway support needs a separate FFI
entrypoint that takes a `SOCKET` handle instead of an `int` fd.
