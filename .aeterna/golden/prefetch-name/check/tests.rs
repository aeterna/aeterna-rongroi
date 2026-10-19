// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// Golden check for parse_prefetch_name(). check/run.py compiles this file with the fixture; it is not a crate.

#[path = "../fixture/prefetch_name.rs"]
mod fixture;

use fixture::parse_prefetch_name;

#[test]
fn parses_name_and_hash() {
    assert_eq!(
        parse_prefetch_name("A-1A2B3C4D-0BADF00D.pf"),
        Some(("A-1A2B3C4D".to_string(), 0x0BADF00D))
    );
}

#[test]
fn extension_is_case_insensitive() {
    assert_eq!(
        parse_prefetch_name("FAKEAPP.EXE-0BADF00D.PF"),
        Some(("FAKEAPP.EXE".to_string(), 0x0BADF00D))
    );
}

#[test]
fn hash_accepts_lowercase_hex() {
    assert_eq!(
        parse_prefetch_name("x-1a2b3c4d.pf"),
        Some(("x".to_string(), 0x1a2b3c4d))
    );
}

#[test]
fn splits_at_the_last_dash() {
    assert_eq!(parse_prefetch_name("A-B-0000000F.pf"), Some(("A-B".to_string(), 0xF)));
}

#[test]
fn keeps_non_ascii_name_and_all_ones_hash() {
    assert_eq!(
        parse_prefetch_name("ทดสอบ-FFFFFFFF.pf"),
        Some(("ทดสอบ".to_string(), 0xFFFF_FFFF))
    );
}

#[test]
fn accepts_zero_hash() {
    assert_eq!(parse_prefetch_name("A-00000000.pf"), Some(("A".to_string(), 0)));
}

#[test]
fn rejects_path_separators() {
    assert_eq!(parse_prefetch_name(r"C:\Temp\A-1A2B3C4D-0BADF00D.pf"), None);
    assert_eq!(parse_prefetch_name("dir/A-1A2B3C4D-0BADF00D.pf"), None);
}

#[test]
fn rejects_hash_that_is_not_eight_hex_digits() {
    assert_eq!(parse_prefetch_name("A-1A2B3C4.pf"), None);
    assert_eq!(parse_prefetch_name("A-1A2B3C4DE.pf"), None);
    assert_eq!(parse_prefetch_name("A-0x12345678.pf"), None);
    assert_eq!(parse_prefetch_name("A-1A2B3C4G.pf"), None);
}

#[test]
fn rejects_signed_hash() {
    assert_eq!(parse_prefetch_name("A-+1234567.pf"), None);
}

#[test]
fn rejects_empty_name() {
    assert_eq!(parse_prefetch_name("-0BADF00D.pf"), None);
}

#[test]
fn rejects_missing_dash_or_stem() {
    assert_eq!(parse_prefetch_name("NODASH.pf"), None);
    assert_eq!(parse_prefetch_name(".pf"), None);
}

#[test]
fn rejects_other_extensions() {
    assert_eq!(parse_prefetch_name("A-1A2B3C4D-0BADF00D.exe"), None);
    assert_eq!(parse_prefetch_name("A-1A2B3C4D-0BADF00D"), None);
    assert_eq!(parse_prefetch_name("A-1A2B3C4D-0BADF00D.pf.bak"), None);
}
