// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! A PE file's version resource: the `OriginalFilename` its build recorded, and nothing else from the
//! resource (ADR 0078 section 8). The input is a whole PE file; this module walks its header, section
//! table and resource tree only far enough to reach `RT_VERSION`, then its `StringFileInfo` tables.
//! Only the first `OriginalFilename` leaves it; a PE without one is `Ok(None)`, not an error.

use crate::error::ParseError;

// PE header and section table (ADR 0078 section 8: MZ, 0x40 <= e_lfanew <= 4096, PE\0\0).
const E_LFANEW_OFFSET: usize = 0x3C;
const E_LFANEW_MIN: u32 = 0x40;
const E_LFANEW_MAX: u32 = 4096;
const PE32_MAGIC: u16 = 0x10B;
const PE32_PLUS_MAGIC: u16 = 0x20B;
const RESOURCE_DIRECTORY_INDEX: usize = 2;
/// The Windows loader refuses an image with more sections than this.
const MAX_SECTIONS: usize = 96;

// Resource tree layout and the bounds a hostile directory cannot exceed.
const RT_VERSION: u32 = 16;
const RESOURCE_ENTRY_LEN: usize = 8;
/// The 24 bytes of data-directory entries this parser reads from the optional header.
const DATA_DIRECTORY_REACH: usize = 24;
const SUBDIRECTORY_FLAG: u32 = 0x8000_0000;
const OFFSET_MASK: u32 = 0x7FFF_FFFF;
const NAME_IS_STRING: u32 = 0x8000_0000;
const MAX_RESOURCE_DEPTH: usize = 3;
const MAX_DIRECTORY_ENTRIES: usize = 4096;
const MAX_VISITED_ENTRIES: usize = 16_384;

const VERSION_NODE_HEADER_LEN: usize = 6;
const DWORD_ALIGN: usize = 4;

macro_rules! bad {
    ($field:literal, $detail:literal) => {
        return Err(malformed($field, $detail))
    };
}

macro_rules! need {
    ($value:expr, $field:literal) => {
        $value.ok_or_else(|| malformed($field, "a required field is missing or truncated"))?
    };
}

struct PeImage {
    number_of_sections: usize,
    sections_offset: usize,
    resource_rva: u32,
}

type ResourceDirectory = (usize, u32);

struct VersionNode<'a> {
    key: String,
    value: &'a [u8],
    value_type: u16,
    end: usize,
    children_start: usize,
}

/// Reads the first `OriginalFilename` in a PE file's version resource.
///
/// Returns `Ok(None)` when there is no resource directory, `RT_VERSION` or `OriginalFilename`; a
/// structurally unreadable PE, section or resource is a [`ParseError`] naming the part.
pub fn original_filename(bytes: &[u8]) -> Result<Option<String>, ParseError> {
    let Some(image) = pe_image(bytes)? else {
        return Ok(None);
    };
    let Some((data_rva, data_size)) = version_data(bytes, &image)? else {
        return Ok(None);
    };
    let data_length = usize::try_from(data_size)
        .map_err(|_| malformed("version_info", "the version resource is too long"))?;
    let offset = rva_to_offset(bytes, &image, data_rva, data_length)?;
    let end = need!(offset.checked_add(data_length), "version_info");
    let data = need!(bytes.get(offset..end), "version_info");
    let root = version_node(data, 0, data.len())?;
    if root.key != "VS_VERSION_INFO" {
        bad!("version_info", "the root key is not VS_VERSION_INFO");
    }
    for child in version_children(data, &root)? {
        if child.key == "StringFileInfo" {
            for table in version_children(data, &child)? {
                if let Some(string) = version_children(data, &table)?
                    .into_iter()
                    .find(|string| string.key == "OriginalFilename")
                {
                    if string.value_type != 1 {
                        bad!("version_info", "an OriginalFilename value is not text");
                    }
                    let (units, rest) = string.value.as_chunks::<2>();
                    if !rest.is_empty() {
                        bad!("version_info", "an odd-length string");
                    }
                    return char::decode_utf16(
                        units
                            .iter()
                            .map(|pair| u16::from_le_bytes(*pair))
                            .take_while(|&unit| unit != 0),
                    )
                    .collect::<Result<String, _>>()
                    .map_err(|_| {
                        malformed("version_info", "an OriginalFilename value is not UTF-16")
                    })
                    .map(Some);
                }
            }
        }
    }
    Ok(None)
}

fn pe_image(bytes: &[u8]) -> Result<Option<PeImage>, ParseError> {
    if !bytes.starts_with(b"MZ") {
        bad!("pe_header", "no MZ header");
    }
    let e_lfanew = need!(u32_at(bytes, E_LFANEW_OFFSET), "pe_header");
    if !(E_LFANEW_MIN..=E_LFANEW_MAX).contains(&e_lfanew) {
        bad!("pe_header", "e_lfanew is out of range");
    }
    let pe_offset = usize::try_from(e_lfanew)
        .map_err(|_| malformed("pe_header", "e_lfanew does not fit this platform"))?;
    let signature_end = need!(pe_offset.checked_add(4), "pe_header");
    if bytes.get(pe_offset..signature_end) != Some(b"PE\0\0".as_slice()) {
        bad!("pe_header", "no PE signature");
    }
    let optional = need!(signature_end.checked_add(20), "pe_header");
    if optional > bytes.len() {
        bad!("pe_header", "the COFF header is truncated");
    }
    let number_of_sections = usize::from(need!(u16_at(bytes, signature_end + 2), "pe_header"));
    if number_of_sections > MAX_SECTIONS {
        bad!("pe_header", "the section count exceeds the loader limit");
    }
    let optional_size = usize::from(need!(u16_at(bytes, signature_end + 16), "pe_header"));
    let optional_end = need!(optional.checked_add(optional_size), "pe_header");
    if optional_end > bytes.len() {
        bad!("pe_header", "the optional header is truncated");
    }
    let magic = need!(u16_at(bytes, optional), "pe_header");
    let (rva_count_offset, directories_offset) = match magic {
        PE32_MAGIC => (92, 96),
        PE32_PLUS_MAGIC => (108, 112),
        _ => bad!("pe_header", "an unknown optional-header magic"),
    };
    let directory_end = directories_offset + DATA_DIRECTORY_REACH;
    if rva_count_offset + 4 > optional_size || directory_end > optional_size {
        bad!("pe_header", "the optional header is too short");
    }
    let rva_count_field = need!(optional.checked_add(rva_count_offset), "pe_header");
    let number_of_rva_and_sizes = need!(u32_at(bytes, rva_count_field), "pe_header");
    if usize::try_from(number_of_rva_and_sizes).unwrap_or(0) <= RESOURCE_DIRECTORY_INDEX {
        return Ok(None);
    }
    let resource_entry = need!(
        optional.checked_add(directories_offset + RESOURCE_DIRECTORY_INDEX * RESOURCE_ENTRY_LEN),
        "pe_header"
    );
    let resource_rva = need!(u32_at(bytes, resource_entry), "pe_header");
    let resource_size = need!(u32_at(bytes, resource_entry + 4), "pe_header");
    if resource_rva == 0 || resource_size == 0 {
        return Ok(None);
    }
    Ok(Some(PeImage {
        number_of_sections,
        sections_offset: optional_end,
        resource_rva,
    }))
}

fn rva_to_offset(
    bytes: &[u8],
    image: &PeImage,
    rva: u32,
    length: usize,
) -> Result<usize, ParseError> {
    let wanted = u64::from(rva);
    for index in 0..image.number_of_sections {
        let Some(section_offset) = index
            .checked_mul(40)
            .and_then(|offset| image.sections_offset.checked_add(offset))
        else {
            continue;
        };
        let Some(section) = section_offset
            .checked_add(40)
            .and_then(|end| bytes.get(section_offset..end))
        else {
            continue;
        };
        // VirtualSize, VirtualAddress, SizeOfRawData and PointerToRawData.
        let virtual_size = need!(u32_at(section, 8), "section");
        let virtual_address = need!(u32_at(section, 12), "section");
        let raw_size = need!(u32_at(section, 16), "section");
        let raw_pointer = need!(u32_at(section, 20), "section");
        let start = u64::from(virtual_address);
        let Some(end) = start.checked_add(u64::from(virtual_size.max(raw_size))) else {
            continue;
        };
        if wanted < start || wanted >= end {
            continue;
        }
        let delta = usize::try_from(wanted - start)
            .map_err(|_| malformed("section", "a section offset does not fit this platform"))?;
        let raw_size = usize::try_from(raw_size)
            .map_err(|_| malformed("section", "a section size does not fit this platform"))?;
        if need!(delta.checked_add(length), "section") > raw_size {
            bad!("section", "a read runs past the section's raw data");
        }
        let raw_pointer = usize::try_from(raw_pointer).map_err(|_| {
            malformed(
                "section",
                "a section file offset does not fit this platform",
            )
        })?;
        let file_offset = need!(raw_pointer.checked_add(delta), "section");
        if need!(file_offset.checked_add(length), "section") > bytes.len() {
            bad!("section", "a section runs past the file");
        }
        return Ok(file_offset);
    }
    Err(malformed("section", "an RVA lies outside every section"))
}

fn resource_bytes<'a>(
    bytes: &'a [u8],
    image: &PeImage,
    offset: u32,
    length: usize,
) -> Result<&'a [u8], ParseError> {
    let rva = need!(image.resource_rva.checked_add(offset), "resource_directory");
    let file_offset = rva_to_offset(bytes, image, rva, length)?;
    let end = need!(file_offset.checked_add(length), "resource_directory");
    need!(bytes.get(file_offset..end), "resource_directory");
    Ok(bytes.get(file_offset..end).unwrap_or_default())
}

fn resource_directory(
    bytes: &[u8],
    image: &PeImage,
    offset: u32,
) -> Result<ResourceDirectory, ParseError> {
    let header = resource_bytes(bytes, image, offset, 16)?;
    let named = need!(u16_at(header, 12), "resource_directory");
    let ids = need!(u16_at(header, 14), "resource_directory");
    let entries = usize::from(named) + usize::from(ids);
    if entries > MAX_DIRECTORY_ENTRIES {
        bad!("resource_directory", "a directory claims too many entries");
    }
    let first_entry = need!(offset.checked_add(16), "resource_directory");
    Ok((entries, first_entry))
}

fn directory_entry(
    bytes: &[u8],
    image: &PeImage,
    directory: &ResourceDirectory,
    index: usize,
) -> Result<(u32, u32), ParseError> {
    let index = u32::try_from(index)
        .ok()
        .and_then(|index| index.checked_mul(u32::try_from(RESOURCE_ENTRY_LEN).ok()?))
        .ok_or_else(|| malformed("resource_directory", "a directory entry index overflows"))?;
    let offset = need!(directory.1.checked_add(index), "resource_directory");
    let entry = resource_bytes(bytes, image, offset, RESOURCE_ENTRY_LEN)
        .map_err(|_| malformed("resource_directory", "a directory entry is truncated"))?;
    Ok((
        need!(u32_at(entry, 0), "resource_directory"),
        need!(u32_at(entry, 4), "resource_directory"),
    ))
}

fn version_data(bytes: &[u8], image: &PeImage) -> Result<Option<(u32, u32)>, ParseError> {
    let mut directory_offset = 0u32;
    let mut depth = 0usize;
    let mut visited = vec![0u32];
    let mut visited_entries = 0usize;
    loop {
        let directory = resource_directory(bytes, image, directory_offset)?;
        let mut chosen = None;
        for index in 0..directory.0 {
            visited_entries = need!(visited_entries.checked_add(1), "resource_directory");
            if visited_entries > MAX_VISITED_ENTRIES {
                bad!("resource_directory", "the walk visits too many entries");
            }
            let (name, offset) = directory_entry(bytes, image, &directory, index)?;
            if depth != 0 || (name & NAME_IS_STRING == 0 && name == RT_VERSION) {
                chosen = Some(offset);
                break;
            }
        }
        let Some(offset) = chosen else {
            return Ok(None);
        };
        let is_subdirectory = offset & SUBDIRECTORY_FLAG != 0;
        let relative = offset & OFFSET_MASK;
        if depth == MAX_RESOURCE_DEPTH - 1 {
            if is_subdirectory {
                bad!("resource_directory", "a resource directory is too deep");
            }
            let entry = resource_bytes(bytes, image, relative, 16)
                .map_err(|_| malformed("resource_directory", "a data entry is truncated"))?;
            return Ok(Some((
                need!(u32_at(entry, 0), "resource_directory"),
                need!(u32_at(entry, 4), "resource_directory"),
            )));
        }
        if !is_subdirectory {
            bad!("resource_directory", "a data entry above the language");
        }
        if visited.contains(&relative) {
            bad!("resource_directory", "a resource directory cycle");
        }
        visited.push(relative);
        directory_offset = relative;
        depth += 1;
    }
}

fn version_node(
    data: &[u8],
    start: usize,
    parent_end: usize,
) -> Result<VersionNode<'_>, ParseError> {
    let header_end = need!(
        start
            .checked_add(VERSION_NODE_HEADER_LEN)
            .filter(|&end| end <= parent_end && end <= data.len()),
        "version_info"
    );
    let length = usize::from(need!(u16_at(data, start), "version_info"));
    let value_length = usize::from(need!(u16_at(data, start + 2), "version_info"));
    let value_type = need!(u16_at(data, start + 4), "version_info");
    if length < VERSION_NODE_HEADER_LEN {
        bad!("version_info", "a node is too short");
    }
    let end = need!(
        start
            .checked_add(length)
            .filter(|&end| end <= parent_end && end <= data.len()),
        "version_info"
    );
    let key_start = header_end;
    let key_end = (key_start..end)
        .step_by(2)
        .find(|&at| u16_at(data, at) == Some(0))
        .ok_or_else(|| malformed("version_info", "an unterminated key"))?;
    let (units, rest) = data[key_start..key_end].as_chunks::<2>();
    if !rest.is_empty() {
        bad!("version_info", "a node key has an odd byte count");
    }
    let key = char::decode_utf16(units.iter().map(|pair| u16::from_le_bytes(*pair)))
        .collect::<Result<String, _>>()
        .map_err(|_| malformed("version_info", "a node key is not UTF-16"))?;
    let value_start = need!(
        key_end
            .checked_add(2)
            .and_then(align_dword)
            .filter(|&offset| offset <= end),
        "version_info"
    );
    let value_bytes = if value_type == 1 {
        need!(value_length.checked_mul(2), "version_info")
    } else {
        value_length
    };
    let value_end = need!(
        value_start
            .checked_add(value_bytes)
            .filter(|&value_end| value_end <= end),
        "version_info"
    );
    let value = need!(data.get(value_start..value_end), "version_info");
    let children_start = align_dword(value_end)
        .filter(|&offset| offset <= end)
        .unwrap_or(end);
    Ok(VersionNode {
        key,
        value,
        value_type,
        end,
        children_start,
    })
}

fn version_children<'a>(
    data: &'a [u8],
    parent: &VersionNode<'a>,
) -> Result<Vec<VersionNode<'a>>, ParseError> {
    let mut children = Vec::new();
    let mut cursor = parent.children_start;
    while cursor
        .checked_add(VERSION_NODE_HEADER_LEN)
        .is_some_and(|header_end| header_end <= parent.end)
    {
        let Some(length) = u16_at(data, cursor) else {
            break;
        };
        if length == 0 {
            break;
        }
        let child = version_node(data, cursor, parent.end)?;
        let next = need!(align_dword(child.end), "version_info");
        if next <= cursor {
            bad!("version_info", "a node does not advance");
        }
        children.push(child);
        cursor = next;
    }
    Ok(children)
}

fn align_dword(value: usize) -> Option<usize> {
    value
        .checked_add(DWORD_ALIGN - 1)
        .map(|rounded| rounded & !(DWORD_ALIGN - 1))
}

fn malformed(field: &'static str, detail: &'static str) -> ParseError {
    ParseError::Malformed {
        field,
        detail: detail.to_owned(),
    }
}

fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    let field = bytes.get(offset..offset.checked_add(2)?)?;
    <[u8; 2]>::try_from(field).ok().map(u16::from_le_bytes)
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    let field = bytes.get(offset..offset.checked_add(4)?)?;
    <[u8; 4]>::try_from(field).ok().map(u32::from_le_bytes)
}

#[cfg(test)]
#[allow(
    clippy::cast_possible_truncation,
    clippy::decimal_bitwise_operands,
    clippy::bool_to_int_with_if,
    clippy::manual_is_multiple_of,
    clippy::doc_markdown
)]
mod tests {
    use super::original_filename;
    use crate::error::ParseError;

    const PE_OFFSET: usize = 0x80;
    const PE32_MAGIC: u16 = 0x10B;
    const PE32_PLUS_MAGIC: u16 = 0x20B;
    const RESOURCE_RVA: u32 = 0x1000;
    const FILE_ALIGNMENT: usize = 0x200;
    const RT_VERSION: u32 = 16;
    const RT_MANIFEST: u32 = 24;

    fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn align_up(value: usize, alignment: usize) -> usize {
        value.div_ceil(alignment) * alignment
    }

    fn utf16(text: &str) -> Vec<u8> {
        text.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    fn pad_to_dword(bytes: &mut Vec<u8>) {
        while bytes.len() % 4 != 0 {
            bytes.push(0);
        }
    }

    /// One VS_VERSIONINFO node: its key, its value and its children.
    struct Node {
        key: String,
        value: Vec<u8>,
        value_length: u16,
        value_type: u16,
        children: Vec<Node>,
    }

    /// A `String` node: `wValueLength` counts WCHARs, with the terminating NUL when `terminated`.
    fn string_node(key: &str, value: &str, terminated: bool) -> Node {
        let mut value_bytes = utf16(value);
        let mut value_length =
            u16::try_from(value_bytes.len() / 2).expect("a test value fits in u16");
        if terminated {
            value_bytes.extend_from_slice(&0u16.to_le_bytes());
            value_length += 1;
        }
        Node {
            key: key.to_owned(),
            value: value_bytes,
            value_length,
            value_type: 1,
            children: Vec::new(),
        }
    }

    fn container_node(key: &str, children: Vec<Node>) -> Node {
        Node {
            key: key.to_owned(),
            value: Vec::new(),
            value_length: 0,
            value_type: 1,
            children,
        }
    }

    fn fixed_file_info() -> Vec<u8> {
        let mut value = vec![0u8; 52];
        write_u32(&mut value, 0, 0xFEEF_04BD);
        value
    }

    fn write_node(node: &Node, out: &mut Vec<u8>) {
        let start = out.len();
        out.extend_from_slice(&[0; 6]);
        out.extend_from_slice(&utf16(&node.key));
        out.extend_from_slice(&[0, 0]);
        pad_to_dword(out);
        out.extend_from_slice(&node.value);
        pad_to_dword(out);
        for (index, child) in node.children.iter().enumerate() {
            if index > 0 {
                pad_to_dword(out);
            }
            write_node(child, out);
        }
        let length =
            u16::try_from(out.len() - start).expect("a test version structure fits in u16");
        write_u16(out, start, length);
        write_u16(out, start + 2, node.value_length);
        write_u16(out, start + 4, node.value_type);
    }

    fn table_key(index: usize) -> &'static str {
        if index == 0 { "040904B0" } else { "040904E4" }
    }

    fn version_info(tables: &[&[(&str, &str)]], terminated: bool) -> Vec<u8> {
        let string_tables = tables
            .iter()
            .enumerate()
            .map(|(index, table)| {
                let strings = table
                    .iter()
                    .map(|(key, value)| string_node(key, value, terminated))
                    .collect();
                container_node(table_key(index), strings)
            })
            .collect();
        let root = Node {
            key: "VS_VERSION_INFO".to_owned(),
            value: fixed_file_info(),
            value_length: 52,
            value_type: 0,
            children: vec![container_node("StringFileInfo", string_tables)],
        };
        let mut bytes = Vec::new();
        write_node(&root, &mut bytes);
        bytes
    }

    /// A resource section whose bytes hold the three-level tree the walk expects.
    struct Resource {
        bytes: Vec<u8>,
        data_entry_offset: Option<usize>,
        blob_offset: usize,
    }

    /// Root directory → type → first name → first language → data entry → `blob`.
    fn resource_tree(resource_type: u32, blob: &[u8]) -> Resource {
        let directory_size = 16 + 8;
        let root = 0usize;
        let type_directory = directory_size;
        let name_directory = directory_size * 2;
        let data_entry = directory_size * 3;
        let blob_offset = data_entry + 16;
        let mut bytes = vec![0u8; blob_offset];

        write_u16(&mut bytes, root + 14, 1);
        write_u32(&mut bytes, root + 16, resource_type);
        write_u32(&mut bytes, root + 20, (type_directory as u32) | 0x8000_0000);

        write_u16(&mut bytes, type_directory + 14, 1);
        write_u32(&mut bytes, type_directory + 16, 1);
        write_u32(
            &mut bytes,
            type_directory + 20,
            (name_directory as u32) | 0x8000_0000,
        );

        write_u16(&mut bytes, name_directory + 14, 1);
        write_u32(&mut bytes, name_directory + 16, 0x0409);
        write_u32(&mut bytes, name_directory + 20, data_entry as u32);

        write_u32(
            &mut bytes,
            data_entry + 4,
            u32::try_from(blob.len()).expect("a test blob fits in u32"),
        );
        bytes.extend_from_slice(blob);

        Resource {
            bytes,
            data_entry_offset: Some(data_entry),
            blob_offset,
        }
    }

    fn version_resource(tables: &[&[(&str, &str)]], terminated: bool) -> Resource {
        resource_tree(RT_VERSION, &version_info(tables, terminated))
    }

    /// A type directory whose first entry points back to the root directory.
    fn resource_with_a_cycle() -> Resource {
        let mut bytes = vec![0u8; 48];
        write_u16(&mut bytes, 14, 1);
        write_u32(&mut bytes, 16, RT_VERSION);
        write_u32(&mut bytes, 20, 24u32 | 0x8000_0000);

        write_u16(&mut bytes, 24 + 14, 1);
        write_u32(&mut bytes, 24 + 16, 1);
        write_u32(&mut bytes, 24 + 20, 0x8000_0000);
        Resource {
            bytes,
            data_entry_offset: None,
            blob_offset: 0,
        }
    }

    /// A type directory claiming 100000 ID entries with none of them written.
    fn resource_claiming_many_entries() -> Resource {
        let mut bytes = vec![0u8; 40];
        write_u16(&mut bytes, 14, 1);
        write_u32(&mut bytes, 16, RT_VERSION);
        write_u32(&mut bytes, 20, 24u32 | 0x8000_0000);
        write_u16(&mut bytes, 24 + 12, 50_000);
        write_u16(&mut bytes, 24 + 14, 50_000);
        Resource {
            bytes,
            data_entry_offset: None,
            blob_offset: 0,
        }
    }

    /// A PE image with one `.rsrc` section, or none when `resource` is absent.
    fn pe(magic: u16, resource: Option<&Resource>) -> Vec<u8> {
        build_pe(magic, resource, None)
    }

    fn pe_with_data_rva(magic: u16, resource: &Resource, data_rva: u32) -> Vec<u8> {
        build_pe(magic, Some(resource), Some(data_rva))
    }

    fn build_pe(magic: u16, resource: Option<&Resource>, data_rva: Option<u32>) -> Vec<u8> {
        let optional_header_size = if magic == PE32_PLUS_MAGIC { 0xF0 } else { 0xE0 };
        let raw_offset = FILE_ALIGNMENT;
        let resource_length = resource.map_or(0, |resource| resource.bytes.len());
        let raw_size = if resource.is_some() {
            align_up(resource_length, FILE_ALIGNMENT)
        } else {
            0
        };
        let mut bytes = vec![0u8; raw_offset + raw_size];

        bytes[0..2].copy_from_slice(b"MZ");
        write_u32(
            &mut bytes,
            0x3C,
            u32::try_from(PE_OFFSET).expect("the constant fits in u32"),
        );
        bytes[PE_OFFSET..PE_OFFSET + 4].copy_from_slice(b"PE\0\0");

        let coff = PE_OFFSET + 4;
        write_u16(&mut bytes, coff, 0x8664);
        write_u16(&mut bytes, coff + 2, if resource.is_some() { 1 } else { 0 });
        write_u16(
            &mut bytes,
            coff + 16,
            u16::try_from(optional_header_size).expect("the constant fits in u16"),
        );
        let optional = coff + 20;
        write_u16(&mut bytes, optional, magic);

        let (rva_count_offset, directories_offset) = if magic == PE32_PLUS_MAGIC {
            (108, 112)
        } else {
            (92, 96)
        };
        let number_of_rva_and_sizes = if resource.is_some() { 16 } else { 0 };
        write_u32(
            &mut bytes,
            optional + rva_count_offset,
            number_of_rva_and_sizes,
        );

        if let Some(resource) = resource {
            write_u32(&mut bytes, optional + directories_offset + 16, RESOURCE_RVA);
            write_u32(
                &mut bytes,
                optional + directories_offset + 20,
                u32::try_from(resource_length).expect("a test resource fits in u32"),
            );

            let section = optional + optional_header_size;
            bytes[section..section + 8].copy_from_slice(b".rsrc\0\0\0");
            write_u32(
                &mut bytes,
                section + 8,
                u32::try_from(resource_length).expect("a test resource fits in u32"),
            );
            write_u32(&mut bytes, section + 12, RESOURCE_RVA);
            write_u32(
                &mut bytes,
                section + 16,
                u32::try_from(raw_size).expect("a test section fits in u32"),
            );
            write_u32(
                &mut bytes,
                section + 20,
                u32::try_from(raw_offset).expect("a test offset fits in u32"),
            );

            bytes[raw_offset..raw_offset + resource_length].copy_from_slice(&resource.bytes);

            if let Some(data_entry_offset) = resource.data_entry_offset {
                let rva = data_rva.unwrap_or_else(|| {
                    RESOURCE_RVA
                        + u32::try_from(resource.blob_offset)
                            .expect("a test blob offset fits in u32")
                });
                write_u32(&mut bytes, raw_offset + data_entry_offset, rva);
            }
        }

        bytes
    }

    fn png() -> Vec<u8> {
        let mut bytes = Vec::from([0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);
        bytes.extend_from_slice(&13u32.to_be_bytes());
        bytes.extend_from_slice(b"IHDR");
        bytes.extend_from_slice(&[0; 13]);
        bytes.extend_from_slice(&[0; 4]);
        bytes
    }

    fn malformed_field(bytes: &[u8]) -> &'static str {
        match original_filename(bytes) {
            Err(ParseError::Malformed { field, .. }) => field,
            other => panic!("expected a Malformed error, got {other:?}"),
        }
    }

    #[test]
    fn v1_pe32_original_filename_is_read() {
        let resource = version_resource(&[&[("OriginalFilename", "loader.exe")]], true);
        let bytes = pe(PE32_MAGIC, Some(&resource));
        assert_eq!(original_filename(&bytes), Ok(Some("loader.exe".to_owned())));
    }

    #[test]
    fn v2_pe32_plus_original_filename_is_read() {
        let resource = version_resource(&[&[("OriginalFilename", "loader.exe")]], true);
        let bytes = pe(PE32_PLUS_MAGIC, Some(&resource));
        assert_eq!(original_filename(&bytes), Ok(Some("loader.exe".to_owned())));
    }

    #[test]
    fn v3_a_pe_without_a_resource_directory_has_no_original_filename() {
        let bytes = pe(PE32_MAGIC, None);
        assert_eq!(original_filename(&bytes), Ok(None));
    }

    #[test]
    fn v3_b_resources_without_rt_version_have_no_original_filename() {
        let blob = version_info(&[&[("OriginalFilename", "loader.exe")]], true);
        let resource = resource_tree(RT_MANIFEST, &blob);
        let bytes = pe(PE32_MAGIC, Some(&resource));
        assert_eq!(original_filename(&bytes), Ok(None));
    }

    #[test]
    fn v3_c_original_filename_in_the_second_string_table_is_found() {
        let resource = version_resource(
            &[
                &[("CompanyName", "Contoso")],
                &[("OriginalFilename", "second.exe")],
            ],
            true,
        );
        let bytes = pe(PE32_MAGIC, Some(&resource));
        assert_eq!(original_filename(&bytes), Ok(Some("second.exe".to_owned())));
    }

    #[test]
    fn v4_a_data_rva_outside_every_section_is_a_section_error() {
        let resource = version_resource(&[&[("OriginalFilename", "loader.exe")]], true);
        let bytes = pe_with_data_rva(PE32_MAGIC, &resource, 0x9000);
        assert_eq!(malformed_field(&bytes), "section");
    }

    #[test]
    fn v4_b_truncated_version_info_is_a_version_info_error() {
        let mut blob = version_info(&[&[("OriginalFilename", "loader.exe")]], true);
        blob.truncate(20);
        let resource = resource_tree(RT_VERSION, &blob);
        let bytes = pe(PE32_MAGIC, Some(&resource));
        assert_eq!(malformed_field(&bytes), "version_info");
    }

    #[test]
    fn v5_a_directory_entry_pointing_to_its_parent_is_a_resource_directory_error() {
        let resource = resource_with_a_cycle();
        let bytes = pe(PE32_MAGIC, Some(&resource));
        assert_eq!(malformed_field(&bytes), "resource_directory");
    }

    #[test]
    fn v5_b_directory_claiming_too_many_entries_is_a_resource_directory_error() {
        let resource = resource_claiming_many_entries();
        let bytes = pe(PE32_MAGIC, Some(&resource));
        assert_eq!(malformed_field(&bytes), "resource_directory");
    }

    #[test]
    fn v7_more_than_96_sections_is_a_pe_header_error() {
        let resource = version_resource(&[&[("OriginalFilename", "loader.exe")]], true);
        let mut bytes = pe(PE32_MAGIC, Some(&resource));
        write_u16(&mut bytes, PE_OFFSET + 4 + 2, 97);
        assert_eq!(malformed_field(&bytes), "pe_header");
    }

    #[test]
    fn v6_png_and_empty_input_are_pe_header_errors() {
        for bytes in [png(), Vec::new()] {
            assert_eq!(malformed_field(&bytes), "pe_header");
        }
    }

    #[test]
    fn c1_version_resource_without_original_filename_is_none() {
        let resource = version_resource(&[&[("CompanyName", "Contoso")]], true);
        let bytes = pe(PE32_MAGIC, Some(&resource));
        assert_eq!(original_filename(&bytes), Ok(None));
    }

    #[test]
    fn c1_a_value_without_its_terminating_nul_is_still_read() {
        let resource = version_resource(&[&[("OriginalFilename", "loader.exe")]], false);
        let bytes = pe(PE32_MAGIC, Some(&resource));
        assert_eq!(original_filename(&bytes), Ok(Some("loader.exe".to_owned())));
    }
}
