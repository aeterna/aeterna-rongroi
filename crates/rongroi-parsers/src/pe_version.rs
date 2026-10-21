// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! A PE file's version resource: the `OriginalFilename` its build recorded, and nothing else from the
//! resource (ADR 0078 section 8).

#[cfg(test)]
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
