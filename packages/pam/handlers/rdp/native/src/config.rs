//! Connector config. Only CredSSP-relevant fields matter; after CredSSP
//! we switch to byte passthrough, so other fields are just shape-fillers.

use ironrdp_connector::{BitmapConfig, Config, Credentials, DesktopSize};
use ironrdp_pdu::gcc::KeyboardType;
use ironrdp_pdu::rdp::capability_sets::{BitmapCodecs, MajorPlatformType};
use ironrdp_pdu::rdp::client_info::{PerformanceFlags, TimezoneInfo};

pub const DEFAULT_WIDTH: u16 = 1920;
pub const DEFAULT_HEIGHT: u16 = 1080;

pub fn connector_config(username: String, password: String) -> Config {
    Config {
        desktop_size: DesktopSize {
            width: DEFAULT_WIDTH,
            height: DEFAULT_HEIGHT,
        },
        desktop_scale_factor: 0,

        // Advertise HYBRID_EX|HYBRID|SSL to match what native clients send.
        // Windows App validates the target's echoed clientRequestedProtocols
        // against what it sent on the acceptor side; if the sets diverge it
        // disconnects right after Connect Response.
        enable_tls: true,
        enable_credssp: true,

        credentials: Credentials::UsernamePassword { username, password },
        domain: None,

        // Shape-fillers: unused after CredSSP (see module doc).
        client_build: 0,
        client_name: String::new(),
        keyboard_type: KeyboardType::IbmEnhanced,
        keyboard_subtype: 0,
        keyboard_functional_keys_count: 12,
        keyboard_layout: 0,
        ime_file_name: String::new(),
        bitmap: Some(BitmapConfig {
            lossy_compression: false,
            color_depth: 32,
            codecs: BitmapCodecs(Vec::new()),
        }),
        dig_product_id: String::new(),
        client_dir: String::new(),
        platform: MajorPlatformType::UNSPECIFIED,
        hardware_id: None,
        request_data: None,
        autologon: false,
        enable_audio_playback: false,
        performance_flags: PerformanceFlags::default(),
        license_cache: None,
        timezone_info: TimezoneInfo::default(),
        enable_server_pointer: false,
        pointer_software_rendering: false,
    }
}
