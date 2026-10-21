// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! What a file's own bytes say it is: its content kind, whether bytes follow its end, and whether a
//! PE header starts inside it (ADR 0078 section 8).

#[cfg(test)]
mod tests {
    use super::{FileKind, parse};

    const SUBSYSTEM_NATIVE: u16 = 1;
    const SUBSYSTEM_WINDOWS_GUI: u16 = 2;
    const PE_OFFSET: usize = 0x80;
    const OPTIONAL_HEADER_SIZE: usize = 0xE0;
    const PNG_SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];

    fn parse_ok(bytes: &[u8]) -> super::ContentKind {
        parse(bytes).expect("every input is Ok")
    }

    /// A PE32 image with one COFF header and an optional header whose subsystem is readable.
    fn pe(subsystem: u16, dll: bool) -> Vec<u8> {
        let mut bytes = vec![0u8; PE_OFFSET + 4 + 20 + OPTIONAL_HEADER_SIZE];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[0x3C..0x40].copy_from_slice(
            &u32::try_from(PE_OFFSET)
                .expect("the constant fits in u32")
                .to_le_bytes(),
        );
        bytes[PE_OFFSET..PE_OFFSET + 4].copy_from_slice(b"PE\0\0");

        let coff = PE_OFFSET + 4;
        bytes[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        bytes[coff + 16..coff + 18].copy_from_slice(
            &u16::try_from(OPTIONAL_HEADER_SIZE)
                .expect("the constant fits in u16")
                .to_le_bytes(),
        );
        let characteristics = if dll { 0x2000u16 } else { 0 };
        bytes[coff + 18..coff + 20].copy_from_slice(&characteristics.to_le_bytes());

        let optional = coff + 20;
        bytes[optional..optional + 2].copy_from_slice(&0x10Bu16.to_le_bytes());
        bytes[optional + 0x44..optional + 0x46].copy_from_slice(&subsystem.to_le_bytes());
        bytes
    }

    fn crc32(bytes: &[u8]) -> u32 {
        let mut crc = 0xFFFF_FFFFu32;
        for &byte in bytes {
            crc ^= u32::from(byte);
            for _ in 0..8 {
                crc = if crc & 1 != 0 {
                    (crc >> 1) ^ 0xEDB8_8320
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }

    fn png_chunk(kind: &[u8], data: &[u8]) -> Vec<u8> {
        let mut chunk = Vec::new();
        chunk.extend_from_slice(
            &u32::try_from(data.len())
                .expect("a test chunk fits in u32")
                .to_be_bytes(),
        );
        chunk.extend_from_slice(kind);
        chunk.extend_from_slice(data);

        let mut checked = kind.to_vec();
        checked.extend_from_slice(data);
        chunk.extend_from_slice(&crc32(&checked).to_be_bytes());
        chunk
    }

    fn png() -> Vec<u8> {
        let mut bytes = PNG_SIGNATURE.to_vec();
        bytes.extend_from_slice(&png_chunk(
            b"IHDR",
            &[0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0],
        ));
        bytes.extend_from_slice(&png_chunk(b"IEND", &[]));
        bytes
    }

    fn png_with_text(text: &[u8]) -> Vec<u8> {
        let mut bytes = PNG_SIGNATURE.to_vec();
        bytes.extend_from_slice(&png_chunk(
            b"IHDR",
            &[0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0],
        ));
        bytes.extend_from_slice(&png_chunk(b"tEXt", text));
        bytes.extend_from_slice(&png_chunk(b"IEND", &[]));
        bytes
    }

    /// SOI, an APP1 segment that itself holds an EOI, SOS, entropy data with a stuffed `FF 00` and a
    /// restart marker, then the file's real EOI.
    fn jpeg() -> Vec<u8> {
        let mut bytes = Vec::from([0xFF, 0xD8]);

        let app1_payload: &[u8] = b"Exif\0\0\xFF\xD9";
        bytes.extend_from_slice(&[0xFF, 0xE1]);
        bytes.extend_from_slice(
            &u16::try_from(app1_payload.len() + 2)
                .expect("a test payload fits in u16")
                .to_be_bytes(),
        );
        bytes.extend_from_slice(app1_payload);

        // SOS with one component: the length says where the entropy data begins.
        bytes.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00]);
        bytes.extend_from_slice(&[0x01, 0xFF, 0x00, 0x02, 0xFF, 0xD0, 0x03]);
        bytes.extend_from_slice(&[0xFF, 0xD9]);
        bytes
    }

    /// A stored, empty-file ZIP: local header, central directory and an EOCD carrying `comment`.
    fn zip(comment: &[u8]) -> Vec<u8> {
        let name = b"a";
        let data: &[u8] = b"";
        let crc = crc32(data);
        let mut bytes = Vec::new();

        let local_offset = u32::try_from(bytes.len()).expect("a test offset fits in u32");
        bytes.extend_from_slice(&0x0403_4B50u32.to_le_bytes());
        bytes.extend_from_slice(&20u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&crc.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(
            &u16::try_from(name.len())
                .expect("a test name fits in u16")
                .to_le_bytes(),
        );
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(name);

        let central_start = bytes.len();
        bytes.extend_from_slice(&0x0201_4B50u32.to_le_bytes());
        bytes.extend_from_slice(&20u16.to_le_bytes());
        bytes.extend_from_slice(&20u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&crc.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(
            &u16::try_from(name.len())
                .expect("a test name fits in u16")
                .to_le_bytes(),
        );
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&local_offset.to_le_bytes());
        bytes.extend_from_slice(name);

        let central_offset = u32::try_from(central_start).expect("a test offset fits in u32");
        let central_size =
            u32::try_from(bytes.len() - central_start).expect("a test size fits in u32");
        bytes.extend_from_slice(&0x0605_4B50u32.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&central_size.to_le_bytes());
        bytes.extend_from_slice(&central_offset.to_le_bytes());
        bytes.extend_from_slice(
            &u16::try_from(comment.len())
                .expect("a test comment fits in u16")
                .to_le_bytes(),
        );
        bytes.extend_from_slice(comment);
        bytes
    }

    /// A 1x1 GIF with one image block and the `0x3B` trailer.
    fn gif() -> Vec<u8> {
        let mut bytes = Vec::from(*b"GIF89a");
        bytes.extend_from_slice(&[0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00]);
        bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF]);
        bytes.extend_from_slice(&[0x2C, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00]);
        bytes.extend_from_slice(&[0x02, 0x02, 0x4C, 0x01, 0x00]);
        bytes.push(0x3B);
        bytes
    }

    fn bmp() -> Vec<u8> {
        let mut bytes = Vec::from(*b"BM");
        bytes.extend_from_slice(&[0u8; 12]);
        bytes
    }

    fn webp() -> Vec<u8> {
        let mut bytes = Vec::from(*b"RIFF");
        bytes.extend_from_slice(&4u32.to_le_bytes());
        bytes.extend_from_slice(b"WEBP");
        bytes
    }

    fn ico() -> Vec<u8> {
        Vec::from([0x00, 0x00, 0x01, 0x00, 0x01, 0x00])
    }

    #[test]
    fn c1_pe_subsystem_and_dll_bit_choose_the_kind() {
        assert_eq!(
            parse_ok(&pe(SUBSYSTEM_WINDOWS_GUI, false)).kind,
            FileKind::PeExecutable
        );
        assert_eq!(
            parse_ok(&pe(SUBSYSTEM_WINDOWS_GUI, true)).kind,
            FileKind::PeDll
        );
        assert_eq!(
            parse_ok(&pe(SUBSYSTEM_NATIVE, false)).kind,
            FileKind::PeDriver
        );
        assert_eq!(
            parse_ok(&pe(SUBSYSTEM_NATIVE, true)).kind,
            FileKind::PeDriver
        );
    }

    #[test]
    fn c2_png_ending_at_iend_is_an_image_with_no_trailing_data() {
        let description = parse_ok(&png());
        assert_eq!(description.kind, FileKind::Image);
        assert_eq!(description.trailing_data, Some(false));
        assert_eq!(description.embedded_pe, Some(false));
    }

    #[test]
    fn c3_png_with_an_appended_pe_has_trailing_data_and_an_embedded_pe() {
        let mut bytes = png();
        bytes.extend_from_slice(&pe(SUBSYSTEM_WINDOWS_GUI, false));

        let description = parse_ok(&bytes);
        assert_eq!(description.kind, FileKind::Image);
        assert_eq!(description.trailing_data, Some(true));
        assert_eq!(description.embedded_pe, Some(true));
    }

    #[test]
    fn c4_jpeg_trailing_data_ignores_an_eoi_inside_a_segment() {
        let base = jpeg();
        let description = parse_ok(&base);
        assert_eq!(description.kind, FileKind::Image);
        assert_eq!(description.trailing_data, Some(false));
        assert_eq!(description.embedded_pe, Some(false));

        let mut with_tail = base;
        with_tail.push(0);
        assert_eq!(parse_ok(&with_tail).trailing_data, Some(true));
    }

    #[test]
    fn c4_zip_trailing_data_follows_the_end_of_central_directory() {
        let base = zip(b"export");
        let description = parse_ok(&base);
        assert_eq!(description.kind, FileKind::Archive);
        assert_eq!(description.trailing_data, Some(false));

        let mut with_tail = base;
        with_tail.extend_from_slice(b"tail");
        assert_eq!(parse_ok(&with_tail).trailing_data, Some(true));
    }

    #[test]
    fn c4_gif_trailing_data_follows_the_trailer() {
        let base = gif();
        let description = parse_ok(&base);
        assert_eq!(description.kind, FileKind::Image);
        assert_eq!(description.trailing_data, Some(false));

        let mut with_tail = base;
        with_tail.extend_from_slice(b"tail");
        assert_eq!(parse_ok(&with_tail).trailing_data, Some(true));
    }

    #[test]
    fn c5_the_other_image_and_archive_kinds_are_recognised() {
        for (name, bytes) in [
            ("gif", gif()),
            ("bmp", bmp()),
            ("webp", webp()),
            ("ico", ico()),
        ] {
            assert_eq!(parse_ok(&bytes).kind, FileKind::Image, "{name}");
        }

        for (name, bytes) in [
            ("7z", Vec::from([0x37u8, 0x7A, 0xBC, 0xAF, 0x27, 0x1C])),
            ("rar", Vec::from(*b"Rar!\x1A\x07\x00")),
            ("gzip", Vec::from([0x1Fu8, 0x8B, 0x08, 0x00])),
            ("cab", Vec::from(*b"MSCF\0\0\0\0")),
        ] {
            assert_eq!(parse_ok(&bytes).kind, FileKind::Archive, "{name}");
        }
    }

    #[test]
    fn c6_script_text_is_utf8_without_a_nul_in_the_first_4096_bytes() {
        assert_eq!(parse_ok(b"Write-Host hello\n").kind, FileKind::Script);

        let mut with_bom = vec![0xEF, 0xBB, 0xBF];
        with_bom.extend_from_slice(b"echo hello\n");
        assert_eq!(parse_ok(&with_bom).kind, FileKind::Script);

        let mut nul_at_100 = vec![b'a'; 100];
        nul_at_100.push(0);
        nul_at_100.extend_from_slice(b"rest");
        assert_eq!(parse_ok(&nul_at_100).kind, FileKind::Unknown);

        let mut nul_at_5000 = vec![b'a'; 5000];
        nul_at_5000.push(0);
        assert_eq!(parse_ok(&nul_at_5000).kind, FileKind::Script);

        // The 4096-byte limit cuts the three-byte character; the whole input is still valid UTF-8.
        let mut split = vec![b'a'; 4095];
        split.extend_from_slice("€".as_bytes());
        assert_eq!(split.len(), 4098);
        assert_eq!(parse_ok(&split).kind, FileKind::Script);

        let mut utf16 = Vec::new();
        for unit in "hello".encode_utf16() {
            utf16.extend_from_slice(&unit.to_le_bytes());
        }
        assert_eq!(parse_ok(&utf16).kind, FileKind::Unknown);
    }

    #[test]
    fn c7_input_that_is_not_a_readable_pe_is_unknown() {
        assert_ne!(
            parse_ok(&pe(SUBSYSTEM_WINDOWS_GUI, false)).kind,
            FileKind::Unknown
        );
        assert_eq!(parse_ok(b"").kind, FileKind::Unknown);
        assert_eq!(parse_ok(b"MZ").kind, FileKind::Unknown);

        let mut past_end = pe(SUBSYSTEM_WINDOWS_GUI, false);
        let end = u32::try_from(past_end.len()).expect("a test PE fits in u32");
        past_end[0x3C..0x40].copy_from_slice(&end.to_le_bytes());
        assert_eq!(parse_ok(&past_end).kind, FileKind::Unknown);

        let mut below_the_header = pe(SUBSYSTEM_WINDOWS_GUI, false);
        below_the_header[0x3C..0x40].copy_from_slice(&0x10u32.to_le_bytes());
        assert_eq!(parse_ok(&below_the_header).kind, FileKind::Unknown);
    }

    #[test]
    fn c8_embedded_pe_needs_a_readable_header_and_is_left_unknown_for_a_pe() {
        let description = parse_ok(&png_with_text(b"MZ"));
        assert_eq!(description.kind, FileKind::Image);
        assert_eq!(description.embedded_pe, Some(false));

        let mut pe_with_second = pe(SUBSYSTEM_WINDOWS_GUI, false);
        pe_with_second.extend_from_slice(&pe(SUBSYSTEM_WINDOWS_GUI, false));

        let description = parse_ok(&pe_with_second);
        assert_eq!(description.kind, FileKind::PeExecutable);
        assert_eq!(description.embedded_pe, None);
        assert_eq!(description.trailing_data, None);
    }
}
