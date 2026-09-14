// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! QR codes of links into this program's repository, drawn here so that the window needs no
//! JavaScript dependency and no network to show one (ADR 0045).

use qrcode::render::svg;
use qrcode::{EcLevel, QrCode};
use rongroi_core::provenance::REPOSITORY_URL;

/// The longest URL this draws, in bytes.
const MAX_URL_BYTES: usize = 512;

/// An SVG QR code of `url`, or `None` when `url` is not the repository or a page inside it, so that
/// the window cannot use this to encode anything else.
///
/// Inside means: `url` is at most [`MAX_URL_BYTES`] long and is `REPOSITORY_URL` followed by nothing,
/// or by `/` and only ASCII letters, digits, `/`, `.`, `_` and `-`, with no `..` anywhere. So no
/// query, fragment, space, control character or step out of the repository reaches a QR code.
pub fn svg(url: &str) -> Option<String> {
    let inside = url.len() <= MAX_URL_BYTES
        && url.strip_prefix(REPOSITORY_URL).is_some_and(|rest| {
            rest.is_empty()
                || (rest.starts_with('/')
                    && !rest.contains("..")
                    && rest.bytes().all(|b| {
                        b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-')
                    }))
        });
    if !inside {
        return None;
    }
    let code = QrCode::with_error_correction_level(url.as_bytes(), EcLevel::M).ok()?;
    Some(
        code.render::<svg::Color<'_>>()
            .min_dimensions(160, 160)
            .dark_color(svg::Color("#000000"))
            .light_color(svg::Color("#ffffff"))
            .quiet_zone(true)
            .build(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn draws_the_repository_and_a_page_inside_it() {
        let image = svg(
            "https://github.com/aeterna/aeterna-rongroi/tree/2c673c54aeb084cd3773057efbb9ed3b98fd2dbc",
        )
        .expect("a page inside the repository");
        assert!(image.starts_with("<?xml"), "{image}");
        assert!(image.contains("<svg"), "{image}");
        assert!(image.contains("#000000"), "{image}");
        assert!(svg(REPOSITORY_URL).is_some());
        assert!(svg(&format!("{REPOSITORY_URL}/")).is_some());
        assert!(
            svg(&format!(
                "{REPOSITORY_URL}/blob/2c673c54aeb084cd3773057efbb9ed3b98fd2dbc/rules/posture/boot/secure-boot-disabled/rule.yaml"
            ))
            .is_some()
        );
        let longest = format!(
            "{REPOSITORY_URL}/{}",
            "a".repeat(MAX_URL_BYTES - REPOSITORY_URL.len() - 1)
        );
        assert_eq!(longest.len(), MAX_URL_BYTES);
        assert!(svg(&longest).is_some());
    }

    #[test]
    fn refuses_anything_else() {
        for other in [
            "",
            "hello",
            "https://example.com",
            "https://github.com/aeterna/aeterna-rongroi-fork",
            "https://github.com/aeterna",
            "https://github.com/aeterna/aeterna-rongroi/../../other",
            "https://github.com/aeterna/aeterna-rongroi/tree/main/a b",
            "https://github.com/aeterna/aeterna-rongroi/tree/main\nhello",
            "https://github.com/aeterna/aeterna-rongroi/tree?x=1",
            "https://github.com/aeterna/aeterna-rongroi/tree#x",
        ] {
            assert_eq!(svg(other), None, "{other}");
        }
        let too_long = format!(
            "{REPOSITORY_URL}/{}",
            "a".repeat(MAX_URL_BYTES - REPOSITORY_URL.len())
        );
        assert_eq!(too_long.len(), MAX_URL_BYTES + 1);
        assert_eq!(svg(&too_long), None);
    }
}
