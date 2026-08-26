//! Tracing subscriber for the bridge. The crate is linked into the Go CLI as
//! a staticlib, so nothing else installs a subscriber; without this every
//! `tracing` event here and inside IronRDP is discarded before it is
//! formatted, which is why bridge failures used to surface as a bare status
//! code with no output.

use std::sync::Once;

use tracing_subscriber::filter::{LevelFilter, Targets};
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

static INIT: Once = Once::new();

/// Idempotent; safe to call from every FFI entry point.
pub fn init() {
    INIT.call_once(|| {
        let filter = std::env::var("RUST_LOG")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(default_directive);

        // Targets rather than EnvFilter: same `target=level,target=level`
        // syntax, without pulling a regex engine in for span-field matching we
        // never use.
        let targets = filter.parse::<Targets>().unwrap_or_else(|_| {
            Targets::new().with_target("infisical_rdp_bridge", LevelFilter::INFO)
        });

        let fmt_layer = tracing_subscriber::fmt::layer()
            .with_writer(std::io::stderr)
            .with_ansi(false)
            .with_target(true)
            // Thread names make it obvious which half a line came from.
            .with_thread_names(true);

        // try_init (not init) so a host-installed subscriber wins instead of
        // aborting the process.
        let _ = tracing_subscriber::registry()
            .with(fmt_layer)
            .with(targets)
            .try_init();
    });
}

/// Mirrors the Go CLI's LOG_LEVEL so `LOG_LEVEL=debug infisical ...` turns on
/// bridge and IronRDP protocol tracing without a second knob. IronRDP logs
/// each decoded PDU at debug/trace, which is what makes strict-client
/// negotiation failures diagnosable.
///
/// sspi is deliberately pinned to `info` regardless of LOG_LEVEL: it logs
/// serialized TSCredentials, which contain the injected PAM password in
/// cleartext, at debug and below. Enabling it has to be a deliberate
/// `RUST_LOG=sspi=trace`, never a side effect of raising the general log level.
fn default_directive() -> String {
    let level = std::env::var("LOG_LEVEL")
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let level = match level.as_str() {
        "trace" => "trace",
        "debug" => "debug",
        "warn" | "warning" => "warn",
        "error" => "error",
        "fatal" => "error",
        _ => "info",
    };
    format!("infisical_rdp_bridge={level},ironrdp={level},sspi=info")
}
