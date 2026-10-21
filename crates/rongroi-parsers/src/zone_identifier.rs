// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! What a `:Zone.Identifier` stream says about where a file came from: its zone and download host
//! (ADR 0079 section 2).
//!
//! The stream also holds a referrer and the rest of the download URL, which are personal data. This
//! module keeps only the zone id and the host, reduced as [`crate::powershell_text::DownloadHost`]
//! reduces it.

use crate::error::ParseError;
use crate::powershell_text::{DownloadHost, first_url_host};

/// What one `Zone.Identifier` stream says: its zone and its download host, and nothing else.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ZoneIdentifier {
    /// The `ZoneId` number, when the section has one that fits a `u32`.
    pub zone_id: Option<u32>,
    /// The host of `HostUrl`, reduced as [`DownloadHost`] says; `None` when it is absent or is not an
    /// `http`/`https` URL.
    pub host: Option<DownloadHost>,
}

/// Parses a `Zone.Identifier` stream (ADR 0079 section 2).
///
/// Reads UTF-8 with an optional BOM, or UTF-16LE with a BOM. Only `ZoneId` and `HostUrl` in the
/// `[ZoneTransfer]` section are kept; every other key and the rest of each value is dropped here.
///
/// # Errors
///
/// [`ParseError::Malformed`] with the field `"zone_identifier"` when the bytes are not text in either
/// encoding, or when there is no `[ZoneTransfer]` section.
pub fn parse(bytes: &[u8]) -> Result<ZoneIdentifier, ParseError> {
    let text = decode_text(bytes).ok_or_else(not_text)?;
    let mut zone = ZoneIdentifier::default();
    let mut saw_section = false;
    let mut in_section = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') && line.ends_with(']') {
            in_section = line.eq_ignore_ascii_case("[ZoneTransfer]");
            saw_section |= in_section;
            continue;
        }
        if !in_section {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.eq_ignore_ascii_case("ZoneId") {
            zone.zone_id = value.trim().parse::<u32>().ok();
        } else if key.eq_ignore_ascii_case("HostUrl") {
            zone.host = first_url_host(value.trim());
        }
    }
    if saw_section {
        Ok(zone)
    } else {
        Err(ParseError::Malformed {
            field: "zone_identifier",
            detail: "no [ZoneTransfer] section".to_owned(),
        })
    }
}

/// Decodes the stream's text, or `None` when the bytes are not UTF-8 or BOM-marked UTF-16LE.
fn decode_text(bytes: &[u8]) -> Option<String> {
    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        if rest.len() % 2 != 0 {
            return None;
        }
        let units: Vec<u16> = rest
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
            .collect();
        return String::from_utf16(&units).ok();
    }
    let rest = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    std::str::from_utf8(rest).ok().map(str::to_owned)
}

fn not_text() -> ParseError {
    ParseError::Malformed {
        field: "zone_identifier",
        detail: "not UTF-8 or UTF-16LE text".to_owned(),
    }
}

#[cfg(test)]
#[allow(clippy::match_wildcard_for_single_variants)] // any variant other than Malformed must fail the test
mod tests {
    use crate::error::ParseError;
    use crate::powershell_text::{AddressKind, DownloadHost};
    use crate::zone_identifier::{ZoneIdentifier, parse};

    const Z1: &str = "[ZoneTransfer]\r\n\
        ZoneId=3\r\n\
        ReferrerUrl=https://ref.example.org/page\r\n\
        HostUrl=https://dl.example.com/a/b.exe?t=1\r\n";

    fn parse_ok(text: &str) -> ZoneIdentifier {
        parse(text.as_bytes()).expect("a well-formed zone identifier stream parses")
    }

    fn utf16le_with_bom(text: &str) -> Vec<u8> {
        let mut bytes = vec![0xFF, 0xFE];
        for unit in text.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes
    }

    fn assert_z1(result: &ZoneIdentifier) {
        assert_eq!(result.zone_id, Some(3));
        assert_eq!(
            result.host,
            Some(DownloadHost::Name("dl.example.com".to_owned()))
        );
        let debug = format!("{result:?}");
        for dropped in ["ref.example.org", "t=1"] {
            assert!(!debug.contains(dropped), "{dropped} leaked: {debug}");
        }
    }

    fn assert_zone_identifier_error(bytes: &[u8]) {
        let Err(error) = parse(bytes) else {
            panic!("expected a zone identifier error");
        };
        match error {
            ParseError::Malformed { field, .. } => assert_eq!(field, "zone_identifier"),
            other => panic!("expected ParseError::Malformed, got {other:?}"),
        }
    }

    #[test]
    fn z1_keeps_zone_id_and_host_but_not_referrer_or_query() {
        assert_z1(&parse_ok(Z1));
    }

    #[test]
    fn z2_host_url_reduces_to_a_lowercased_host() {
        let text = "[ZoneTransfer]\r\nZoneId=3\r\n\
                    HostUrl=https://User:Passw0rd@CDN.Example.COM:8443/a/b.exe?k=SECRET\r\n";
        let result = parse_ok(text);
        assert_eq!(
            result.host,
            Some(DownloadHost::Name("cdn.example.com".to_owned()))
        );
        let debug = format!("{result:?}");
        for dropped in ["User", "Passw0rd", "8443", "SECRET", "a/b.exe"] {
            assert!(!debug.contains(dropped), "{dropped} leaked: {debug}");
        }
    }

    #[test]
    fn z3_an_address_host_is_only_its_kind() {
        let result =
            parse_ok("[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=http://192.168.1.7:8080/a.exe\r\n");
        assert_eq!(
            result.host,
            Some(DownloadHost::Address(AddressKind::Private))
        );
        let debug = format!("{result:?}");
        assert!(!debug.contains("192.168"), "address leaked: {debug}");
    }

    #[test]
    fn z4_utf16le_with_bom_parses_the_same_text() {
        let result = parse(&utf16le_with_bom(Z1)).expect("UTF-16LE with a BOM parses");
        assert_z1(&result);
    }

    #[test]
    fn z5_missing_keys_and_unreadable_zone_ids_are_none() {
        let zone_only = parse_ok("[ZoneTransfer]\r\nZoneId=3\r\n");
        assert_eq!(zone_only.zone_id, Some(3));
        assert_eq!(zone_only.host, None);

        let about = parse_ok("[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=about:internet\r\n");
        assert_eq!(about.zone_id, Some(3));
        assert_eq!(about.host, None);

        for line in ["ZoneId=abc", "ZoneId=4294967296"] {
            let result = parse_ok(&format!("[ZoneTransfer]\r\n{line}\r\n"));
            assert_eq!(result.zone_id, None, "{line}");
            assert_eq!(result.host, None, "{line}");
        }

        let empty = parse_ok("[ZoneTransfer]\r\n");
        assert_eq!(empty.zone_id, None);
        assert_eq!(empty.host, None);
    }

    #[test]
    fn z6_not_text_or_no_zone_transfer_section_is_an_error() {
        assert_zone_identifier_error(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR");
        assert_zone_identifier_error(b"[InternetShortcut]\r\nURL=https://example.org/\r\n");
    }
}
