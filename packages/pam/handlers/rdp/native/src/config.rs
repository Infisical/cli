//! Shared config builder for the connector.
//!
//! Keeps the Config construction in one place so client-mode and proxy-mode
//! use the same defaults when opening the outbound RDP connection to the
//! target.

use ironrdp_connector::{BitmapConfig, Config, Credentials};
use ironrdp_pdu::gcc::KeyboardType;
use ironrdp_pdu::rdp::capability_sets::{BitmapCodecs, MajorPlatformType};
use ironrdp_pdu::rdp::client_info::{PerformanceFlags, TimezoneInfo};

pub fn connector_config(username: String, password: String, width: u16, height: u16) -> Config {
    Config {
        desktop_size: ironrdp_connector::DesktopSize { width, height },
        desktop_scale_factor: 0,

        // Browser-first architecture: we want NLA on the target side, no
        // legacy TLS-only fallback. Target must speak CredSSP/NLA.
        enable_tls: false,
        enable_credssp: true,

        credentials: Credentials::UsernamePassword { username, password },
        domain: None,

        client_build: 0,
        client_name: "infisical-pam".to_owned(),
        keyboard_type: KeyboardType::IbmEnhanced,
        keyboard_subtype: 0,
        keyboard_functional_keys_count: 12,
        keyboard_layout: 0,
        ime_file_name: String::new(),

        // Constrain the connector's codec negotiation: basic bitmap only,
        // no RemoteFX / NSCodec. The acceptor advertises the same minimal
        // set to the inbound client, so both handshakes land on the same
        // format and raw-byte forwarding works without transcoding.
        bitmap: Some(BitmapConfig {
            lossy_compression: false,
            color_depth: 32,
            codecs: BitmapCodecs(Vec::new()),
        }),
        dig_product_id: String::new(),
        client_dir: "C:\\Windows\\System32\\mstscax.dll".to_owned(),

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
