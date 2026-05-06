//! Byte-level patches for Confirm Active / Client Info PDUs.
//! IronRDP's typed decode->encode loses unrelated fields, so we mutate in place.

/// MS-RDPBCGR 2.2.7
pub mod cap_types {
    pub const ORDER: u16 = 0x0003;
    pub const BITMAP_CODECS: u16 = 0x001d;
}

/// MS-RDPBCGR 2.2.7.1.3
pub mod order_cap {
    use std::ops::Range;

    pub const BODY_LEN: usize = 84;
    pub const ORDER_SUPPORT: Range<usize> = 32..64;

    /// Forces server to fall back to Bitmap updates.
    /// orderFlags untouched so NEGOTIATEORDERSUPPORT (mandatory) stays set.
    pub fn clear_order_support(body: &mut [u8]) {
        body[ORDER_SUPPORT].fill(0);
    }
}

/// MS-RDPBCGR 2.2.7.2.10
pub mod bitmap_codecs_cap {
    pub const CODEC_COUNT_OFFSET: usize = 0;
    pub const MIN_BODY_LEN: usize = 1;

    /// Prevents server from picking RFX/NSCodec/AVC.
    pub fn clear_codec_count(body: &mut [u8]) {
        body[CODEC_COUNT_OFFSET] = 0;
    }
}

/// MS-RDPBCGR 2.2.1.11.1.1, given user_data of an MCS Send Data Request
/// whose security header has SEC_INFO_PKT set.
pub mod client_info {
    use std::ops::Range;

    /// 4 bytes security header + 4 bytes CodePage.
    pub const FLAGS: Range<usize> = 8..12;
    pub const INFO_COMPRESSION: u32 = 0x0000_0080;
    pub const COMPRESSION_TYPE_MASK: u32 = 0x0000_1E00;

    /// Disables MPPC bulk compression (IronRDP-session can't decompress it).
    pub fn clear_compression(user_data: &mut [u8]) -> bool {
        if user_data.len() < FLAGS.end {
            return false;
        }
        let bytes: [u8; 4] = match user_data[FLAGS.clone()].try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };
        let flags = u32::from_le_bytes(bytes);
        let new_flags = flags & !(INFO_COMPRESSION | COMPRESSION_TYPE_MASK);
        if flags == new_flags {
            return false;
        }
        user_data[FLAGS.clone()].copy_from_slice(&new_flags.to_le_bytes());
        true
    }
}

#[derive(Debug, Clone, Copy)]
pub struct WalkedCap {
    pub cap_type: u16,
    pub cap_len: usize,
    pub body_offset_in_user_data: usize,
}

/// Stops on a malformed cap header.
pub fn walk_caps(user_data: &[u8], caps_start: usize) -> CapIter<'_> {
    CapIter {
        user_data,
        cursor: caps_start,
    }
}

pub struct CapIter<'a> {
    user_data: &'a [u8],
    cursor: usize,
}

impl<'a> Iterator for CapIter<'a> {
    type Item = WalkedCap;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor + 4 > self.user_data.len() {
            return None;
        }
        let cap_type = u16::from_le_bytes([
            self.user_data[self.cursor],
            self.user_data[self.cursor + 1],
        ]);
        let cap_len = u16::from_le_bytes([
            self.user_data[self.cursor + 2],
            self.user_data[self.cursor + 3],
        ]) as usize;
        if cap_len < 4 || self.cursor + cap_len > self.user_data.len() {
            return None;
        }
        let item = WalkedCap {
            cap_type,
            cap_len,
            body_offset_in_user_data: self.cursor + 4,
        };
        self.cursor += cap_len;
        Some(item)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn order_clear_zeros_only_the_support_array() {
        let mut body = vec![0xff_u8; order_cap::BODY_LEN];
        order_cap::clear_order_support(&mut body);
        assert_eq!(&body[order_cap::ORDER_SUPPORT], &[0; 32]);
        assert_eq!(&body[28..32], &[0xff; 4]);
        assert_eq!(&body[64..68], &[0xff; 4]);
    }

    #[test]
    fn bitmap_codecs_clears_only_first_byte() {
        let mut body = vec![0xff_u8; 16];
        bitmap_codecs_cap::clear_codec_count(&mut body);
        assert_eq!(body[0], 0);
        assert_eq!(&body[1..], &[0xff; 15]);
    }

    #[test]
    fn client_info_clears_compression_bits() {
        let mut user_data = vec![0u8; 12];
        user_data[8..12].copy_from_slice(&0x0000_1E80_u32.to_le_bytes());
        assert!(client_info::clear_compression(&mut user_data));
        let new_flags = u32::from_le_bytes(user_data[8..12].try_into().unwrap());
        assert_eq!(new_flags, 0);
    }

    #[test]
    fn client_info_noop_when_compression_already_off() {
        let mut user_data = vec![0u8; 12];
        user_data[8..12].copy_from_slice(&0x0000_0040_u32.to_le_bytes());
        assert!(!client_info::clear_compression(&mut user_data));
    }

    #[test]
    fn client_info_returns_false_when_user_data_too_short() {
        let mut user_data = vec![0u8; 11];
        assert!(!client_info::clear_compression(&mut user_data));
    }

    #[test]
    fn client_info_preserves_unrelated_flag_bits() {
        let mut user_data = vec![0xAB_u8; 12];
        // INFO_COMPRESSION + CompressionTypeMask + INFO_AUTOLOGON(0x0008) + INFO_UNICODE(0x0010)
        let original = 0x0000_1E80_u32 | 0x0000_0008 | 0x0000_0010;
        user_data[8..12].copy_from_slice(&original.to_le_bytes());
        assert!(client_info::clear_compression(&mut user_data));
        let new_flags = u32::from_le_bytes(user_data[8..12].try_into().unwrap());
        assert_eq!(new_flags, 0x0000_0008 | 0x0000_0010);
        assert_eq!(&user_data[..8], &[0xAB; 8]);
    }

    #[test]
    fn walk_caps_iterates_each_cap() {
        let mut user_data = vec![0u8; 8];
        user_data.extend_from_slice(&[0x01, 0x00, 0x08, 0x00, 0xaa, 0xbb, 0xcc, 0xdd]);
        user_data.extend_from_slice(&[
            0x03, 0x00, 0x0c, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        ]);
        let caps: Vec<_> = walk_caps(&user_data, 8).collect();
        assert_eq!(caps.len(), 2);
        assert_eq!(caps[0].cap_type, 0x0001);
        assert_eq!(caps[0].cap_len, 8);
        assert_eq!(caps[0].body_offset_in_user_data, 12);
        assert_eq!(caps[1].cap_type, 0x0003);
        assert_eq!(caps[1].cap_len, 12);
        assert_eq!(caps[1].body_offset_in_user_data, 20);
    }

    #[test]
    fn walk_caps_stops_on_malformed_header() {
        let mut user_data = vec![0u8; 4];
        user_data.extend_from_slice(&[0x01, 0x00, 0x64, 0x00]);
        let caps: Vec<_> = walk_caps(&user_data, 4).collect();
        assert_eq!(caps.len(), 0);
    }

    #[test]
    fn walk_caps_stops_on_cap_len_below_header_size() {
        let user_data = vec![0x01, 0x00, 0x02, 0x00];
        let caps: Vec<_> = walk_caps(&user_data, 0).collect();
        assert_eq!(caps.len(), 0);
    }

    /// End-to-end byte-preservation contract: walk a synthetic caps array
    /// containing Order, BitmapCodecs, and an unrelated cap; patch only
    /// the targeted fields; assert every other byte is identical.
    #[test]
    fn walk_and_patch_preserves_unrelated_bytes() {
        let mut buf: Vec<u8> = Vec::new();

        // Cap 1: unrelated cap_type=0x0001, len=8, body filled with 0x77
        buf.extend_from_slice(&[0x01, 0x00, 0x08, 0x00]);
        buf.extend_from_slice(&[0x77; 4]);
        let unrelated_range = 0..buf.len();

        // Cap 2: Order (0x0003), full body of 0xFF + 4-byte header
        let order_header_offset = buf.len();
        let order_total_len = (order_cap::BODY_LEN + 4) as u16;
        buf.extend_from_slice(&[0x03, 0x00]);
        buf.extend_from_slice(&order_total_len.to_le_bytes());
        let order_body_offset = buf.len();
        buf.extend_from_slice(&vec![0xFF; order_cap::BODY_LEN]);

        // Cap 3: BitmapCodecs (0x001d), 4-byte header + body of 0xEE
        let codecs_header_offset = buf.len();
        let codecs_body_len = 16usize;
        buf.extend_from_slice(&[0x1D, 0x00]);
        buf.extend_from_slice(&((codecs_body_len + 4) as u16).to_le_bytes());
        let codecs_body_offset = buf.len();
        buf.extend_from_slice(&vec![0xEE; codecs_body_len]);

        // Cap 4: trailing unrelated cap (filter must not stop early or read past it)
        let trailing_offset = buf.len();
        buf.extend_from_slice(&[0x02, 0x00, 0x06, 0x00, 0x55, 0x55]);

        let original = buf.clone();

        let caps: Vec<_> = walk_caps(&buf, 0).collect();
        assert_eq!(caps.len(), 4);
        assert_eq!(caps[0].body_offset_in_user_data, order_header_offset - 4);
        assert_eq!(caps[1].cap_type, cap_types::ORDER);
        assert_eq!(caps[1].body_offset_in_user_data, order_body_offset);
        assert_eq!(caps[2].cap_type, cap_types::BITMAP_CODECS);
        assert_eq!(caps[2].body_offset_in_user_data, codecs_body_offset);
        assert_eq!(caps[3].body_offset_in_user_data, trailing_offset + 4);

        order_cap::clear_order_support(
            &mut buf[order_body_offset..order_body_offset + order_cap::BODY_LEN],
        );
        bitmap_codecs_cap::clear_codec_count(&mut buf[codecs_body_offset..]);

        // Unrelated cap: byte-identical
        assert_eq!(&buf[unrelated_range.clone()], &original[unrelated_range]);
        // Order cap: header preserved, only ORDER_SUPPORT range zeroed
        assert_eq!(
            &buf[order_header_offset..order_body_offset],
            &original[order_header_offset..order_body_offset]
        );
        let zeroed_start = order_body_offset + order_cap::ORDER_SUPPORT.start;
        let zeroed_end = order_body_offset + order_cap::ORDER_SUPPORT.end;
        assert_eq!(
            &buf[order_body_offset..zeroed_start],
            &original[order_body_offset..zeroed_start]
        );
        assert_eq!(&buf[zeroed_start..zeroed_end], &[0u8; 32]);
        assert_eq!(
            &buf[zeroed_end..codecs_header_offset],
            &original[zeroed_end..codecs_header_offset]
        );
        // BitmapCodecs cap: header preserved, only first body byte zeroed
        assert_eq!(
            &buf[codecs_header_offset..codecs_body_offset],
            &original[codecs_header_offset..codecs_body_offset]
        );
        assert_eq!(buf[codecs_body_offset], 0);
        assert_eq!(
            &buf[codecs_body_offset + 1..trailing_offset],
            &original[codecs_body_offset + 1..trailing_offset]
        );
        // Trailing cap: byte-identical
        assert_eq!(&buf[trailing_offset..], &original[trailing_offset..]);
    }
}
