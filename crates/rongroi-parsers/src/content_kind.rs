// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! What a file's own bytes say it is: its content kind, whether bytes follow its end, and whether a
//! PE header starts inside it (ADR 0078 section 8).
//!
//! The input is the whole file as the collector read it; the collection layer's size cap is not this
//! module's. Of those bytes it returns one [`ContentKind`]: what the signatures and headers say the
//! file is, whether bytes follow a PNG, JPEG, GIF or ZIP end marker, and whether a readable PE header
//! starts at a non-zero offset. It never returns a path, a name, a hash or a judgement: those belong
//! to the collector and the rules above it (ADR 0013, ADR 0002).

use crate::error::ParseError;

/// Where a PE image's `e_lfanew` field starts.
const E_LFANEW_OFFSET: usize = 0x3C;
/// The smallest `e_lfanew` that leaves room for the DOS header.
const E_LFANEW_MIN: usize = 0x40;
/// The largest `e_lfanew` this parser follows: a header further in is not one Windows loads.
const E_LFANEW_MAX: usize = 4096;
/// The COFF file header that follows `PE\0\0`.
const COFF_HEADER_LEN: usize = 20;
/// `Subsystem` in a PE32 or PE32+ optional header.
const OPTIONAL_SUBSYSTEM_OFFSET: usize = 0x44;
/// The optional header must reach the end of `Subsystem` for the value to be readable.
const OPTIONAL_SUBSYSTEM_NEEDED: usize = OPTIONAL_SUBSYSTEM_OFFSET + 2;
/// `IMAGE_FILE_DLL` in `Characteristics`.
const DLL_CHARACTERISTICS: u16 = 0x2000;
/// `IMAGE_SUBSYSTEM_NATIVE`, which drivers use.
const SUBSYSTEM_NATIVE: u16 = 1;
/// The NUL-free window that decides whether bytes are text.
const SCRIPT_NUL_WINDOW: usize = 4096;
const PNG_SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
const ZIP_EOCD: [u8; 4] = [b'P', b'K', 0x05, 0x06];

/// What a file's bytes say it is (ADR 0078 section 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FileKind {
    /// A PE image that is neither native-subsystem nor marked as a DLL.
    PeExecutable,
    /// A PE image whose COFF characteristics carry `IMAGE_FILE_DLL`.
    PeDll,
    /// A PE image whose optional header names the native subsystem.
    PeDriver,
    /// A ZIP, 7z, RAR, gzip or cabinet archive.
    Archive,
    /// A PNG, JPEG, GIF, BMP, WebP or ICO image.
    Image,
    /// UTF-8 text without a NUL in its first 4096 bytes.
    Script,
    /// Bytes that are none of the above, including an unreadable `MZ`/PE header.
    Unknown,
}

impl FileKind {
    /// The value a report carries for this kind.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PeExecutable => "pe_executable",
            Self::PeDll => "pe_dll",
            Self::PeDriver => "pe_driver",
            Self::Archive => "archive",
            Self::Image => "image",
            Self::Script => "script",
            Self::Unknown => "unknown",
        }
    }
}

/// What one file's bytes describe, of what ADR 0078 section 8 asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContentKind {
    /// What the bytes say the file is.
    pub kind: FileKind,
    /// Whether bytes follow the end marker of a PNG, JPEG, GIF or ZIP.
    ///
    /// `None` for another kind, for a PE, and for one of those four whose walk did not reach a
    /// readable end marker.
    pub trailing_data: Option<bool>,
    /// Whether a readable PE header starts at an offset greater than zero.
    ///
    /// `None` when [`Self::kind`] is a PE kind: an installer legitimately embeds another PE, so the
    /// flag would say nothing about that file.
    pub embedded_pe: Option<bool>,
}

/// Parses one file's whole bytes.
///
/// This returns `Ok` for every input, including an empty slice and arbitrary bytes: "not a PE, not an
/// archive, not text" is a description, not a failure. The [`ParseError`] in the signature is the
/// crate's one parser contract (ADR 0013), so a caller treats this parser like every other.
pub fn parse(bytes: &[u8]) -> Result<ContentKind, ParseError> {
    let kind = classify(bytes);
    Ok(ContentKind {
        kind,
        trailing_data: trailing_data(bytes, kind),
        embedded_pe: (!is_pe(kind)).then(|| contains_pe(bytes)),
    })
}

fn is_pe(kind: FileKind) -> bool {
    matches!(
        kind,
        FileKind::PeExecutable | FileKind::PeDll | FileKind::PeDriver
    )
}

fn classify(bytes: &[u8]) -> FileKind {
    if let Some(header) = pe_at(bytes, 0) {
        return if header.subsystem == SUBSYSTEM_NATIVE {
            FileKind::PeDriver
        } else if header.characteristics & DLL_CHARACTERISTICS != 0 {
            FileKind::PeDll
        } else {
            FileKind::PeExecutable
        };
    }
    if bytes.starts_with(b"MZ") {
        // A DOS/PE marker whose header cannot be read is not text, whatever the rest of it is.
        return FileKind::Unknown;
    }
    if is_archive(bytes) {
        return FileKind::Archive;
    }
    if is_image(bytes) {
        return FileKind::Image;
    }
    if is_script(bytes) {
        return FileKind::Script;
    }
    FileKind::Unknown
}

/// The two COFF header fields that choose a PE kind.
struct PeHeader {
    subsystem: u16,
    characteristics: u16,
}

/// The readable PE header starting at `base`, if there is one.
fn pe_at(bytes: &[u8], base: usize) -> Option<PeHeader> {
    if !starts_with_at(bytes, base, b"MZ") {
        return None;
    }
    let lfanew_field = base.checked_add(E_LFANEW_OFFSET)?;
    let e_lfanew = usize::try_from(u32_at(bytes, lfanew_field)?).ok()?;
    if !(E_LFANEW_MIN..=E_LFANEW_MAX).contains(&e_lfanew) {
        return None;
    }
    let signature = base.checked_add(e_lfanew)?;
    if !starts_with_at(bytes, signature, b"PE\0\0") {
        return None;
    }
    let coff = signature.checked_add(4)?;
    let coff_end = coff.checked_add(COFF_HEADER_LEN)?;
    bytes.get(coff..coff_end)?;
    let optional_size = usize::from(u16_at(bytes, coff + 16)?);
    if optional_size < OPTIONAL_SUBSYSTEM_NEEDED {
        return None;
    }
    let optional_end = coff_end.checked_add(optional_size)?;
    if optional_end > bytes.len() {
        return None;
    }
    Some(PeHeader {
        subsystem: u16_at(bytes, coff_end + OPTIONAL_SUBSYSTEM_OFFSET)?,
        characteristics: u16_at(bytes, coff + 18)?,
    })
}

fn is_archive(bytes: &[u8]) -> bool {
    is_zip(bytes)
        || bytes.starts_with(b"7z\xBC\xAF\x27\x1C")
        || bytes.starts_with(b"Rar!\x1A\x07\x00")
        || bytes.starts_with(b"Rar!\x1A\x07\x01\x00")
        || bytes.starts_with(&[0x1F, 0x8B])
        || bytes.starts_with(b"MSCF")
}

fn is_zip(bytes: &[u8]) -> bool {
    bytes.starts_with(b"PK\x03\x04")
        || bytes.starts_with(b"PK\x05\x06")
        || bytes.starts_with(b"PK\x07\x08")
}

fn is_image(bytes: &[u8]) -> bool {
    bytes.starts_with(&PNG_SIGNATURE)
        || bytes.starts_with(&[0xFF, 0xD8, 0xFF])
        || is_gif(bytes)
        || bytes.starts_with(b"BM")
        || (bytes.starts_with(b"RIFF") && bytes.get(8..12).is_some_and(|tag| tag == b"WEBP"))
        || bytes.starts_with(&[0x00, 0x00, 0x01, 0x00])
}

fn is_gif(bytes: &[u8]) -> bool {
    bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a")
}

/// Whether the whole slice is UTF-8 and the first 4096 bytes hold no NUL.
///
/// The whole slice is validated, not the window: a multi-byte character cut by the 4096-byte limit
/// is still part of a valid character and the file is still text.
fn is_script(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    let window = bytes.get(..SCRIPT_NUL_WINDOW).unwrap_or(bytes);
    !window.contains(&0) && std::str::from_utf8(bytes).is_ok()
}

fn trailing_data(bytes: &[u8], kind: FileKind) -> Option<bool> {
    let end = match kind {
        FileKind::Image if bytes.starts_with(&PNG_SIGNATURE) => png_end(bytes),
        FileKind::Image if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) => jpeg_end(bytes),
        FileKind::Image if is_gif(bytes) => gif_end(bytes),
        FileKind::Archive if is_zip(bytes) => zip_end(bytes),
        _ => return None,
    }?;
    Some(end < bytes.len())
}

/// The end of a PNG's `IEND` chunk, after its CRC.
fn png_end(bytes: &[u8]) -> Option<usize> {
    let mut offset = PNG_SIGNATURE.len();
    loop {
        let length = usize::try_from(u32_be_at(bytes, offset)?).ok()?;
        let chunk_type = bytes.get(offset.checked_add(4)?..offset.checked_add(8)?)?;
        let data_end = offset.checked_add(8)?.checked_add(length)?;
        let chunk_end = data_end.checked_add(4)?;
        if chunk_end > bytes.len() {
            return None;
        }
        if chunk_type == b"IEND" {
            return Some(chunk_end);
        }
        offset = chunk_end;
    }
}

/// The first end-of-image marker in the entropy data that follows `SOS`.
fn jpeg_end(bytes: &[u8]) -> Option<usize> {
    if !bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return None;
    }
    let mut offset = 2;
    loop {
        if *bytes.get(offset)? != 0xFF {
            return None;
        }
        while *bytes.get(offset)? == 0xFF {
            offset += 1;
        }
        let marker = *bytes.get(offset)?;
        offset += 1;
        match marker {
            0x01 | 0xD0..=0xD7 | 0xD8 => {}
            0xD9 => return Some(offset),
            0xDA => {
                let length = usize::from(u16_be_at(bytes, offset)?);
                if length < 2 {
                    return None;
                }
                return jpeg_scan_end(bytes, offset.checked_add(length)?);
            }
            _ => {
                let length = usize::from(u16_be_at(bytes, offset)?);
                if length < 2 {
                    return None;
                }
                offset = offset.checked_add(length)?;
                if offset > bytes.len() {
                    return None;
                }
            }
        }
    }
}

/// The first `EOI` in entropy-coded data, skipping stuffed `FF 00` and restart markers.
fn jpeg_scan_end(bytes: &[u8], mut offset: usize) -> Option<usize> {
    loop {
        if *bytes.get(offset)? != 0xFF {
            offset += 1;
            continue;
        }
        let next = *bytes.get(offset + 1)?;
        if next == 0xD9 {
            return Some(offset + 2);
        }
        // `FF 00` is stuffed data and `FF D0..=FF D7` a restart marker: both stay inside the scan.
        offset += 2;
    }
}

/// The end of a GIF after its `0x3B` trailer.
fn gif_end(bytes: &[u8]) -> Option<usize> {
    if !is_gif(bytes) {
        return None;
    }
    let packed = *bytes.get(10)?;
    let mut offset = 13usize;
    if packed & 0x80 != 0 {
        offset = offset.checked_add(color_table_len(packed).checked_mul(3)?)?;
    }
    loop {
        let block = *bytes.get(offset)?;
        offset += 1;
        match block {
            0x3B => return Some(offset),
            0x2C => {
                let packed = *bytes.get(offset.checked_add(8)?)?;
                offset = offset.checked_add(9)?;
                if packed & 0x80 != 0 {
                    offset = offset.checked_add(color_table_len(packed).checked_mul(3)?)?;
                }
                offset = offset.checked_add(1)?;
                offset = skip_sub_blocks(bytes, offset)?;
            }
            0x21 => {
                offset = offset.checked_add(1)?;
                offset = skip_sub_blocks(bytes, offset)?;
            }
            _ => return None,
        }
    }
}

/// The number of colours a GIF packed field's size bits name.
fn color_table_len(packed: u8) -> usize {
    1usize << (u32::from(packed & 0x07) + 1)
}

/// Skips a GIF sub-block chain and returns the offset after its zero-length terminator.
fn skip_sub_blocks(bytes: &[u8], mut offset: usize) -> Option<usize> {
    loop {
        let length = usize::from(*bytes.get(offset)?);
        offset += 1;
        if length == 0 {
            return Some(offset);
        }
        offset = offset.checked_add(length)?;
        if offset > bytes.len() {
            return None;
        }
    }
}

/// The end of a ZIP's end-of-central-directory record, comment included.
fn zip_end(bytes: &[u8]) -> Option<usize> {
    let mut last = None;
    for (offset, signature) in bytes.windows(ZIP_EOCD.len()).enumerate() {
        if signature != &ZIP_EOCD[..] {
            continue;
        }
        let Some(comment_length) = u16_at(bytes, offset + 20) else {
            continue;
        };
        let end = offset
            .checked_add(22)?
            .checked_add(usize::from(comment_length))?;
        if end == bytes.len() {
            return Some(end);
        }
        last = Some(end);
    }
    last.filter(|&end| end < bytes.len())
}

fn contains_pe(bytes: &[u8]) -> bool {
    (1..bytes.len()).any(|offset| pe_at(bytes, offset).is_some())
}

fn starts_with_at(bytes: &[u8], offset: usize, prefix: &[u8]) -> bool {
    bytes
        .get(offset..)
        .is_some_and(|rest| rest.starts_with(prefix))
}

fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    let field = bytes.get(offset..offset.checked_add(2)?)?;
    <[u8; 2]>::try_from(field).ok().map(u16::from_le_bytes)
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    let field = bytes.get(offset..offset.checked_add(4)?)?;
    <[u8; 4]>::try_from(field).ok().map(u32::from_le_bytes)
}

fn u16_be_at(bytes: &[u8], offset: usize) -> Option<u16> {
    let field = bytes.get(offset..offset.checked_add(2)?)?;
    <[u8; 2]>::try_from(field).ok().map(u16::from_be_bytes)
}

fn u32_be_at(bytes: &[u8], offset: usize) -> Option<u32> {
    let field = bytes.get(offset..offset.checked_add(4)?)?;
    <[u8; 4]>::try_from(field).ok().map(u32::from_be_bytes)
}

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
