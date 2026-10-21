// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! What a `:Zone.Identifier` stream says about where a file came from: its zone and download host
//! (ADR 0079 section 2).
//!
//! The stream also holds a referrer and the rest of the download URL, which are personal data. This
//! module keeps only the zone id and the host, reduced as [`crate::powershell_text::DownloadHost`]
//! reduces it.

#[cfg(test)]
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
