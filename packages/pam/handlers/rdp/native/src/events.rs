//! Structured session events emitted by the bridge's event tap.
//!
//! Phase 1 scope: keyboard input, mouse input, and target-frame metadata.
//! Bitmap-region payload capture (for lossless recording) comes in a later
//! step; this pass just proves the decoder produces usable events.

use std::time::Instant;

use ironrdp_pdu::Action;
use ironrdp_pdu::input::fast_path::KeyboardFlags;
use ironrdp_pdu::input::mouse::PointerFlags;
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub enum SessionEvent {
    /// A scancode key event from the inbound (client) side toward the target.
    KeyboardInput {
        scancode: u8,
        flags: KeyboardFlags,
        elapsed_ns: u64,
    },
    /// Unicode keyboard event (rare; used for IMEs and layouts without scancodes).
    UnicodeInput {
        code_point: u16,
        flags: KeyboardFlags,
        elapsed_ns: u64,
    },
    /// A mouse event from the inbound side. Coordinates are in desktop pixels.
    MouseInput {
        x: u16,
        y: u16,
        flags: PointerFlags,
        wheel_delta: i16,
        elapsed_ns: u64,
    },
    /// One PDU the target sent toward the client, with the raw bytes included
    /// for offline playback. `payload` holds the full FastPath / X.224 PDU
    /// exactly as it came off the wire; decoding (RLE, 16bpp→RGBA, etc.)
    /// happens at replay time in the browser.
    TargetFrame {
        action: Action,
        payload: Vec<u8>,
        elapsed_ns: u64,
    },
}

impl SessionEvent {
    #[allow(dead_code)] // Will be used by Step 2's FFI queue.
    pub fn elapsed_ns(&self) -> u64 {
        match self {
            Self::KeyboardInput { elapsed_ns, .. }
            | Self::UnicodeInput { elapsed_ns, .. }
            | Self::MouseInput { elapsed_ns, .. }
            | Self::TargetFrame { elapsed_ns, .. } => *elapsed_ns,
        }
    }
}

/// Helper to compute nanoseconds since a session-relative `started_at` marker.
pub fn elapsed_ns_since(started_at: Instant) -> u64 {
    started_at.elapsed().as_nanos() as u64
}

pub type EventSender = mpsc::UnboundedSender<SessionEvent>;
pub type EventReceiver = mpsc::UnboundedReceiver<SessionEvent>;

pub fn channel() -> (EventSender, EventReceiver) {
    mpsc::unbounded_channel()
}
