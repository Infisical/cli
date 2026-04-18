//! Capability sets advertised by the acceptor (browser-facing half).
//!
//! Copied almost verbatim from `ironrdp-server::capabilities`. The goal is a
//! conservative, widely-supported set so both the inbound client and the
//! outbound target agree on formats without transcoding. Advanced codecs
//! (RemoteFX, EGFX) are left out deliberately: we want both handshakes to
//! land on basic bitmap.

use ironrdp_pdu::rdp::capability_sets::{
    self, BitmapCodecs, BitmapDrawingFlags, CapabilitySet, CmdFlags, GeneralExtraFlags, InputFlags,
    OrderFlags, OrderSupportExFlags, VirtualChannelFlags, server_codecs_capabilities,
};

const DEFAULT_WIDTH: u16 = 1920;
const DEFAULT_HEIGHT: u16 = 1080;
const MULTIFRAGMENT_MAX_REQUEST_SIZE: u32 = 8 * 1024 * 1024;

pub fn acceptor_capabilities(width: u16, height: u16) -> Vec<CapabilitySet> {
    vec![
        CapabilitySet::General(general()),
        CapabilitySet::Bitmap(bitmap(width, height)),
        CapabilitySet::Order(order()),
        CapabilitySet::SurfaceCommands(surface()),
        CapabilitySet::Pointer(pointer()),
        CapabilitySet::Input(input()),
        CapabilitySet::VirtualChannel(virtual_channel()),
        CapabilitySet::MultiFragmentUpdate(capability_sets::MultifragmentUpdate {
            max_request_size: MULTIFRAGMENT_MAX_REQUEST_SIZE,
        }),
        // Advertise RemoteFX to the browser-side client. Matched by
        // the connector config so both handshakes agree and the bridge
        // forwards RFX-encoded bitmap updates byte-for-byte.
        CapabilitySet::BitmapCodecs(
            server_codecs_capabilities(&[]).unwrap_or_else(|_| BitmapCodecs(Vec::new())),
        ),
    ]
}

pub fn default_desktop_size() -> (u16, u16) {
    (DEFAULT_WIDTH, DEFAULT_HEIGHT)
}

fn general() -> capability_sets::General {
    capability_sets::General {
        extra_flags: GeneralExtraFlags::FASTPATH_OUTPUT_SUPPORTED,
        ..Default::default()
    }
}

fn bitmap(width: u16, height: u16) -> capability_sets::Bitmap {
    capability_sets::Bitmap {
        pref_bits_per_pix: 32,
        desktop_width: width,
        desktop_height: height,
        desktop_resize_flag: true,
        drawing_flags: BitmapDrawingFlags::empty(),
    }
}

fn order() -> capability_sets::Order {
    capability_sets::Order::new(OrderFlags::empty(), OrderSupportExFlags::empty(), 2048, 224)
}

fn surface() -> capability_sets::SurfaceCommands {
    capability_sets::SurfaceCommands {
        flags: CmdFlags::all(),
    }
}

fn pointer() -> capability_sets::Pointer {
    capability_sets::Pointer {
        color_pointer_cache_size: 2048,
        pointer_cache_size: 2048,
    }
}

fn input() -> capability_sets::Input {
    capability_sets::Input {
        input_flags: InputFlags::SCANCODES
            | InputFlags::MOUSE_RELATIVE
            | InputFlags::MOUSEX
            | InputFlags::FASTPATH_INPUT
            | InputFlags::UNICODE
            | InputFlags::FASTPATH_INPUT_2,
        keyboard_layout: 0,
        keyboard_type: None,
        keyboard_subtype: 0,
        keyboard_function_key: 128,
        keyboard_ime_filename: String::new(),
    }
}

fn virtual_channel() -> capability_sets::VirtualChannel {
    capability_sets::VirtualChannel {
        flags: VirtualChannelFlags::NO_COMPRESSION,
        chunk_size: None,
    }
}
