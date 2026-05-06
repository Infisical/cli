//! Bridge tap events. Input is FastPath-decoded c2t; TargetFrame is raw t2c
//! PDU bytes (decoded at replay time in the browser).

use std::time::Instant;

use ironrdp_pdu::input::fast_path::KeyboardFlags;
use ironrdp_pdu::input::mouse::PointerFlags;
use ironrdp_pdu::Action;
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub enum SessionEvent {
    KeyboardInput {
        scancode: u8,
        flags: KeyboardFlags,
        elapsed_ns: u64,
    },
    UnicodeInput {
        code_point: u16,
        flags: KeyboardFlags,
        elapsed_ns: u64,
    },
    MouseInput {
        x: u16,
        y: u16,
        flags: PointerFlags,
        wheel_delta: i16,
        elapsed_ns: u64,
    },
    TargetFrame {
        action: Action,
        payload: Vec<u8>,
        elapsed_ns: u64,
    },
}

pub fn elapsed_ns_since(started_at: Instant) -> u64 {
    started_at.elapsed().as_nanos() as u64
}

pub type EventSender = mpsc::UnboundedSender<SessionEvent>;
pub type EventReceiver = mpsc::UnboundedReceiver<SessionEvent>;

pub fn channel() -> (EventSender, EventReceiver) {
    mpsc::unbounded_channel()
}
