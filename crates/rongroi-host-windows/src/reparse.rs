// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! The bytes `FSCTL_GET_REPARSE_POINT` returns, read as a link's own record without following it
//! (ADR 0091 section 2). Pure Rust, with no Windows API call and no `unsafe`, so it is tested on every
//! platform even though only Windows produces these bytes.

use rongroi_host::{LinkKind, LinkTarget};

/// `IO_REPARSE_TAG_MOUNT_POINT`: a junction or volume mount point.
const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;
/// `IO_REPARSE_TAG_SYMLINK`: a symbolic link.
const IO_REPARSE_TAG_SYMLINK: u32 = 0xA000_000C;
/// The mask that reduces every cloud placeholder tag to one value.
const IO_REPARSE_TAG_CLOUD_MASK: u32 = 0xFFFF_0FFF;
/// The value [`IO_REPARSE_TAG_CLOUD_MASK`] leaves for a cloud placeholder.
const IO_REPARSE_TAG_CLOUD: u32 = 0x9000_001A;
/// `FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS`: reading the placeholder would fetch its data.
const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS: u32 = 0x0040_0000;
/// `FILE_ATTRIBUTE_RECALL_ON_OPEN`: opening the placeholder would fetch its data.
const FILE_ATTRIBUTE_RECALL_ON_OPEN: u32 = 0x0004_0000;
/// `FILE_ATTRIBUTE_OFFLINE`: the file's data is not on this disk, so reading it would fetch it.
const FILE_ATTRIBUTE_OFFLINE: u32 = 0x0000_1000;
/// `SYMLINK_FLAG_RELATIVE`: the symbolic link's target is relative to its folder.
const SYMLINK_FLAG_RELATIVE: u32 = 1;

/// `REPARSE_DATA_BUFFER`'s header: `ReparseTag`, `ReparseDataLength` and `Reserved`.
const REPARSE_HEADER_BYTES: usize = 8;
/// The four `u16` name fields before a mount point's path buffer.
const MOUNT_POINT_NAME_FIELDS_BYTES: usize = 8;
/// The four name fields and the `Flags` word before a symbolic link's path buffer.
const SYMLINK_NAME_AND_FLAGS_BYTES: usize = 12;

const FIELD_PAST_END: &str = "reparse data ends inside a field";

/// Whether reading a path with these `GetFileAttributesW` attributes would fetch data that is not on
/// this disk.
///
/// The placeholder compatibility mode can hide `FILE_ATTRIBUTE_REPARSE_POINT`, so these bits are
/// checked before the reparse tag is read (ADR 0091 section 2).
pub(crate) fn would_fetch(attributes: u32) -> bool {
    attributes
        & (FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
            | FILE_ATTRIBUTE_RECALL_ON_OPEN
            | FILE_ATTRIBUTE_OFFLINE)
        != 0
}

/// `N` bytes at `offset`, for reading a little-endian field.
fn field<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], String> {
    let end = offset
        .checked_add(N)
        .ok_or_else(|| FIELD_PAST_END.to_owned())?;
    bytes
        .get(offset..end)
        .and_then(|slice| <[u8; N]>::try_from(slice).ok())
        .ok_or_else(|| FIELD_PAST_END.to_owned())
}

fn other_target() -> LinkTarget {
    LinkTarget {
        kind: LinkKind::Other,
        target: String::new(),
        relative: false,
    }
}

/// The substitute name of a mount point or symbolic link, as UTF-16LE, from `path_buffer`.
fn name(path_buffer: &[u8], offset: u16, length: u16) -> Result<String, String> {
    let start = usize::from(offset);
    let end = start
        .checked_add(usize::from(length))
        .ok_or_else(|| "reparse name offset and length overflow its data".to_owned())?;
    let bytes = path_buffer
        .get(start..end)
        .ok_or_else(|| "reparse name lies past the end of its data".to_owned())?;
    let (pairs, remainder) = bytes.as_chunks::<2>();
    if !remainder.is_empty() {
        return Err("reparse name has an odd number of bytes".to_owned());
    }
    let units: Vec<u16> = pairs.iter().copied().map(u16::from_le_bytes).collect();
    String::from_utf16(&units).map_err(|_| "reparse name is not valid UTF-16".to_owned())
}

/// Reads the substitute name a link's name fields point at in its path buffer, which begins `fields`
/// bytes into `payload`.
fn read_target(
    payload: &[u8],
    fields: usize,
    kind: LinkKind,
    relative: bool,
) -> Result<LinkTarget, String> {
    let offset = u16::from_le_bytes(field(payload, 0)?);
    let length = u16::from_le_bytes(field(payload, 2)?);
    let path_buffer = payload
        .get(fields..)
        .ok_or_else(|| "reparse data ends before its path buffer".to_owned())?;
    Ok(LinkTarget {
        kind,
        target: name(path_buffer, offset, length)?,
        relative,
    })
}

/// Reads one `REPARSE_DATA_BUFFER` as `FSCTL_GET_REPARSE_POINT` returns it, without following the link
/// it describes (ADR 0091 section 2).
///
/// `attributes` is the `GetFileAttributesW` value for the link. It tells a cloud placeholder whose
/// data is already on the disk from one whose read would fetch it: the former is [`Ok(None)`], read
/// like an ordinary file, and the latter is [`LinkKind::Other`] ([`would_fetch`]).
///
/// Every field and every offset is bounds-checked, so a damaged record is an error rather than a link
/// of some guessed kind.
pub(crate) fn parse_reparse(bytes: &[u8], attributes: u32) -> Result<Option<LinkTarget>, String> {
    let tag = u32::from_le_bytes(field(bytes, 0)?);
    let data_length = usize::from(u16::from_le_bytes(field(bytes, 4)?));
    let payload = bytes
        .get(REPARSE_HEADER_BYTES..)
        .ok_or_else(|| "reparse buffer is shorter than its header".to_owned())?;
    if data_length > payload.len() {
        return Err("reparse data is shorter than the length its header declares".to_owned());
    }
    // Everything after the header is read from the bytes the header says it holds: a name that lies
    // inside the buffer but past this length was not written as part of the record.
    let payload = &payload[..data_length];

    if tag & IO_REPARSE_TAG_CLOUD_MASK == IO_REPARSE_TAG_CLOUD {
        return Ok(would_fetch(attributes).then_some(other_target()));
    }

    match tag {
        IO_REPARSE_TAG_MOUNT_POINT => Ok(Some(read_target(
            payload,
            MOUNT_POINT_NAME_FIELDS_BYTES,
            LinkKind::MountPoint,
            false,
        )?)),
        IO_REPARSE_TAG_SYMLINK => {
            let flags = u32::from_le_bytes(field(payload, MOUNT_POINT_NAME_FIELDS_BYTES)?);
            let relative = flags & SYMLINK_FLAG_RELATIVE != 0;
            Ok(Some(read_target(
                payload,
                SYMLINK_NAME_AND_FLAGS_BYTES,
                LinkKind::Symlink,
                relative,
            )?))
        }
        _ => Ok(Some(other_target())),
    }
}

#[cfg(test)]
mod tests {
    use rongroi_host::{LinkKind, LinkTarget};

    use super::{
        FILE_ATTRIBUTE_OFFLINE, FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS, FILE_ATTRIBUTE_RECALL_ON_OPEN,
        IO_REPARSE_TAG_CLOUD, IO_REPARSE_TAG_MOUNT_POINT, IO_REPARSE_TAG_SYMLINK,
        SYMLINK_FLAG_RELATIVE, parse_reparse, would_fetch,
    };

    /// A `REPARSE_DATA_BUFFER`: the 8-byte header, then `data`.
    fn header(tag: u32, data: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(8 + data.len());
        bytes.extend_from_slice(&tag.to_le_bytes());
        bytes.extend_from_slice(&u16::try_from(data.len()).unwrap().to_le_bytes());
        bytes.extend_from_slice(&0_u16.to_le_bytes());
        bytes.extend_from_slice(data);
        bytes
    }

    /// A mount point or symbolic link: the four name fields, the flags for a link, then `path`.
    fn reparse(
        tag: u32,
        path: &[u8],
        substitute_offset: u16,
        substitute_length: u16,
        print: Option<(u16, u16)>,
        flags: Option<u32>,
    ) -> Vec<u8> {
        let (print_offset, print_length) = print.unwrap_or((0, 0));
        let mut data = Vec::new();
        data.extend_from_slice(&substitute_offset.to_le_bytes());
        data.extend_from_slice(&substitute_length.to_le_bytes());
        data.extend_from_slice(&print_offset.to_le_bytes());
        data.extend_from_slice(&print_length.to_le_bytes());
        if let Some(flags) = flags {
            data.extend_from_slice(&flags.to_le_bytes());
        }
        data.extend_from_slice(path);
        header(tag, &data)
    }

    /// A link whose substitute name is `name`, stored at offset 0.
    fn link(tag: u32, name: &str, flags: Option<u32>) -> Vec<u8> {
        let path: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let length = u16::try_from(path.len()).unwrap();
        reparse(tag, &path, 0, length, None, flags)
    }

    /// A link whose print name comes first in the path buffer, as `CreateSymbolicLink` writes it.
    fn print_name_first(tag: u32, print: &str, substitute: &str, flags: Option<u32>) -> Vec<u8> {
        let print_bytes: Vec<u8> = print.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let substitute_bytes: Vec<u8> =
            substitute.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let print_length = u16::try_from(print_bytes.len()).unwrap();
        let substitute_length = u16::try_from(substitute_bytes.len()).unwrap();
        let mut path = print_bytes;
        path.extend_from_slice(&substitute_bytes);
        reparse(tag, &path, print_length, substitute_length, Some((0, print_length)), flags)
    }

    fn mount_point(name: &str) -> Vec<u8> {
        link(IO_REPARSE_TAG_MOUNT_POINT, name, None)
    }

    fn symlink(name: &str, flags: u32) -> Vec<u8> {
        link(IO_REPARSE_TAG_SYMLINK, name, Some(flags))
    }

    #[test]
    fn a_mount_point_names_its_target() {
        assert_eq!(
            parse_reparse(&mount_point(r"\??\D:\data"), 0),
            Ok(Some(LinkTarget {
                kind: LinkKind::MountPoint,
                target: r"\??\D:\data".to_owned(),
                relative: false,
            }))
        );
    }

    #[test]
    fn an_absolute_symbolic_link_is_not_relative() {
        assert_eq!(
            parse_reparse(&symlink(r"\??\C:\x", 0), 0),
            Ok(Some(LinkTarget {
                kind: LinkKind::Symlink,
                target: r"\??\C:\x".to_owned(),
                relative: false,
            }))
        );
    }

    #[test]
    fn a_relative_symbolic_link_is_relative() {
        assert_eq!(
            parse_reparse(&symlink(r"..\y", SYMLINK_FLAG_RELATIVE), 0),
            Ok(Some(LinkTarget {
                kind: LinkKind::Symlink,
                target: r"..\y".to_owned(),
                relative: true,
            }))
        );
    }

    #[test]
    fn a_unc_symbolic_link_keeps_its_target() {
        assert_eq!(
            parse_reparse(&symlink(r"\??\UNC\srv\share", 0), 0),
            Ok(Some(LinkTarget {
                kind: LinkKind::Symlink,
                target: r"\??\UNC\srv\share".to_owned(),
                relative: false,
            }))
        );
    }

    #[test]
    fn a_hydrated_cloud_placeholder_is_not_a_link() {
        assert_eq!(
            parse_reparse(&header(IO_REPARSE_TAG_CLOUD, &[]), 0),
            Ok(None)
        );
    }

    #[test]
    fn a_cloud_placeholder_that_would_be_fetched_is_other() {
        let bytes = header(IO_REPARSE_TAG_CLOUD, &[]);
        assert_eq!(
            parse_reparse(&bytes, FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS),
            Ok(Some(LinkTarget {
                kind: LinkKind::Other,
                target: String::new(),
                relative: false,
            }))
        );
    }

    #[test]
    fn a_recall_or_offline_attribute_would_fetch() {
        assert!(would_fetch(FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS));
        assert!(would_fetch(FILE_ATTRIBUTE_RECALL_ON_OPEN));
        assert!(would_fetch(FILE_ATTRIBUTE_OFFLINE));
        assert!(!would_fetch(0));
        // The reparse-point bit alone does not fetch anything.
        assert!(!would_fetch(0x0000_0400));
    }

    #[test]
    fn an_unknown_tag_is_other() {
        assert_eq!(
            parse_reparse(&header(0x8000_0001, &[]), 0),
            Ok(Some(LinkTarget {
                kind: LinkKind::Other,
                target: String::new(),
                relative: false,
            }))
        );
    }

    #[test]
    fn a_name_past_the_declared_data_length_is_an_error() {
        // `\??\D:\data` is in the buffer in full, but the header records only the four name fields:
        // the name lies inside the returned bytes and past the data the record declares.
        let mut bytes = mount_point(r"\??\D:\data");
        bytes[4..6].copy_from_slice(&8_u16.to_le_bytes());
        assert!(parse_reparse(&bytes, 0).is_err());
    }

    #[test]
    fn a_buffer_shorter_than_the_header_is_an_error() {
        assert!(parse_reparse(&[0x03, 0x00, 0x00], 0).is_err());
    }

    #[test]
    fn a_name_offset_past_the_end_is_an_error() {
        let bytes = reparse(IO_REPARSE_TAG_MOUNT_POINT, b"ab", 4, 2, None, None);
        assert!(parse_reparse(&bytes, 0).is_err());
    }

    #[test]
    fn an_odd_name_length_is_an_error() {
        let bytes = reparse(IO_REPARSE_TAG_MOUNT_POINT, b"abc", 0, 3, None, None);
        assert!(parse_reparse(&bytes, 0).is_err());
    }

    #[test]
    fn a_name_that_is_not_valid_utf16_is_an_error() {
        let bytes = reparse(IO_REPARSE_TAG_SYMLINK, &[0x00, 0xD8], 0, 2, None, Some(0));
        assert!(parse_reparse(&bytes, 0).is_err());
    }

    #[test]
    fn a_mount_point_whose_print_name_comes_first_names_its_substitute() {
        let bytes = print_name_first(IO_REPARSE_TAG_MOUNT_POINT, r"D:\data", r"\??\D:\data", None);
        assert_eq!(
            parse_reparse(&bytes, 0),
            Ok(Some(LinkTarget {
                kind: LinkKind::MountPoint,
                target: r"\??\D:\data".to_owned(),
                relative: false,
            }))
        );
    }

    #[test]
    fn a_symbolic_link_whose_print_name_comes_first_names_its_substitute() {
        let bytes = print_name_first(IO_REPARSE_TAG_SYMLINK, r"C:\x", r"\??\C:\x", Some(0));
        assert_eq!(
            parse_reparse(&bytes, 0),
            Ok(Some(LinkTarget {
                kind: LinkKind::Symlink,
                target: r"\??\C:\x".to_owned(),
                relative: false,
            }))
        );
    }
}
