// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// Golden check for redact_user_path(). check/run.py compiles this file with the fixture; it is not a crate.

#[path = "../fixture/redact_user_path.rs"]
mod fixture;

use fixture::redact_user_path;

#[test]
fn redacts_profile_name_and_keeps_the_rest() {
    assert_eq!(
        redact_user_path(r"C:\Users\tester\Documents\notes.txt"),
        r"C:\Users\<user>\Documents\notes.txt"
    );
}

#[test]
fn redacts_name_that_ends_the_path() {
    assert_eq!(redact_user_path(r"C:\Users\tester"), r"C:\Users\<user>");
}

#[test]
fn keeps_separator_after_the_name() {
    assert_eq!(redact_user_path(r"C:\Users\tester\"), r"C:\Users\<user>\");
}

#[test]
fn redacts_public_profile() {
    assert_eq!(
        redact_user_path(r"C:\Users\Public\Desktop"),
        r"C:\Users\<user>\Desktop"
    );
}

#[test]
fn redacts_non_ascii_name() {
    assert_eq!(
        redact_user_path(r"D:\Users\ทดสอบ\AppData\Local"),
        r"D:\Users\<user>\AppData\Local"
    );
}

#[test]
fn keeps_users_spelling_and_drive_case() {
    assert_eq!(redact_user_path(r"c:\USERS\tester\a"), r"c:\USERS\<user>\a");
}

#[test]
fn leaves_bare_users_folder_unchanged() {
    assert_eq!(redact_user_path(r"C:\Users"), r"C:\Users");
    assert_eq!(redact_user_path(r"C:\Users\"), r"C:\Users\");
}

#[test]
fn leaves_empty_name_unchanged() {
    assert_eq!(redact_user_path(r"C:\Users\\x"), r"C:\Users\\x");
}

#[test]
fn leaves_prefix_lookalike_unchanged() {
    assert_eq!(redact_user_path(r"C:\UsersX\a"), r"C:\UsersX\a");
}

#[test]
fn leaves_forward_slash_paths_unchanged() {
    assert_eq!(redact_user_path("C:/Users/tester/a"), "C:/Users/tester/a");
}

#[test]
fn leaves_extended_length_prefix_unchanged() {
    assert_eq!(
        redact_user_path(r"\\?\C:\Users\tester\a"),
        r"\\?\C:\Users\tester\a"
    );
}

#[test]
fn leaves_non_letter_drive_unchanged() {
    assert_eq!(redact_user_path(r"1:\Users\tester\a"), r"1:\Users\tester\a");
    assert_eq!(redact_user_path(r"É:\Users\tester\a"), r"É:\Users\tester\a");
}
