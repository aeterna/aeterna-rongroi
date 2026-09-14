// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! QR codes of links into this program's repository, drawn here so that the window needs no
//! JavaScript dependency and no network to show one (ADR 0045).

use qrcode::render::svg;
use qrcode::{EcLevel, QrCode};
use rongroi_core::provenance::REPOSITORY_URL;

/// An SVG QR code of `url`, or `None` when `url` is not the repository or a page inside it, so that
/// the window cannot use this to encode anything else.
pub fn svg(url: &str) -> Option<String> {
    let inside = url
        .strip_prefix(REPOSITORY_URL)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'));
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
    }

    #[test]
    fn refuses_anything_else() {
        for other in [
            "",
            "hello",
            "https://example.com",
            "https://github.com/aeterna/aeterna-rongroi-fork",
            "https://github.com/aeterna",
        ] {
            assert_eq!(svg(other), None, "{other}");
        }
    }
}
