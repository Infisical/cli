//! Tracing subscriber for the bridge. Linked into the Go CLI as a staticlib,
//! so nothing else installs one and without this every event is discarded.

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

        // Targets, not EnvFilter: same syntax without the regex dependency.
        let mut targets = filter.parse::<Targets>().unwrap_or_else(|_| {
            Targets::new().with_target("infisical_rdp_bridge", LevelFilter::INFO)
        });
        // A bare `RUST_LOG=debug` sets the default for every target, sspi
        // included, so cap it unless the caller named sspi themselves.
        if !targets.iter().any(|(target, _)| target.starts_with("sspi")) {
            targets = targets.with_target("sspi", LevelFilter::INFO);
        }

        let fmt_layer = tracing_subscriber::fmt::layer()
            .with_writer(std::io::stderr)
            .with_ansi(false)
            .with_target(true)
            .with_thread_names(true);

        // try_init, not init: a host-installed subscriber should win, not panic.
        let _ = tracing_subscriber::registry()
            .with(fmt_layer)
            .with(targets)
            .try_init();
    });
}

/// Mirrors the Go CLI's LOG_LEVEL so one knob covers both sides.
///
/// sspi stays at `info` whatever LOG_LEVEL says: it logs the injected password
/// in cleartext at debug and below, so enabling it must be deliberate.
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
