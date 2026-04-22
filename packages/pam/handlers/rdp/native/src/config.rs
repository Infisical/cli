//! Connector config for the outbound half of the bridge.
//!
//! Post-CredSSP passthrough means we only need to drive the connector far
//! enough to complete CredSSP. After that, client and target negotiate
//! MCS / capabilities / share state directly through the byte-forwarding
//! pipe. Only CredSSP-relevant fields (credentials, security flags) are
//! load-bearing; other fields are required by `ironrdp_connector::Config`
//! but never hit the wire because we skip `connect_finalize`.

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

        // Advertise the same security-protocol set that native clients
        // typically send (HYBRID_EX | HYBRID | SSL). Target echoes this
        // set back in its ServerCoreData.clientRequestedProtocols; strict
        // clients (Windows App) validate that echo against what THEY sent
        // via the acceptor side. If the sets diverge, Windows App closes
        // the session immediately after Connect Response.
        //
        // Target still picks HYBRID_EX (highest priority) so credential
        // injection via NLA is unaffected. The MITM-downgrade concern
        // described in ironrdp-connector's Config docs is real for a
        // direct client-to-target connection, but here the outbound
        // connection is to a known Windows server over a trusted path
        // (gateway -> target), not a user-facing leg.
        enable_tls: true,
        enable_credssp: true,

        credentials: Credentials::UsernamePassword { username, password },
        domain: None,

        // Unused after CredSSP because we switch to passthrough and target
        // negotiates these values directly with the native client. Kept at
        // sentinel values to satisfy the Config struct shape.
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
