// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! The fixture files under `fixtures/parsers/` are read twice: by the L0 tests and by the fuzz
//! targets, which take the same directories as their seed corpus (ADR 0016). One set of sample
//! bytes, so a fixture added for a parser test improves the fuzz seeds at the same time.
//!
//! Keeping the two ends tied together is this file's job. A directory that is renamed, emptied or
//! dropped would leave the CI fuzz job seeding from nothing, and a fuzzer that starts from nothing
//! still exits 0 — it would report success having never seen a real artifact. These tests fail
//! instead.

use std::path::{Path, PathBuf};

use rongroi_parsers::{bam, evtx, filetime, pca, usn};

/// The directories that are both an L0 fixture set and a fuzz seed corpus.
const SEEDED_DIRECTORIES: [&str; 4] = ["bam", "pca-app-launch", "pca-general", "usn"];

/// `fuzz_prefetch`'s seed corpus, which is the one that does not live under `fixtures/parsers/`:
/// those files are vendored from a third-party corpus under its own licence and `REUSE.toml`
/// annotates them where they are (ADR 0015). The tie to `ci.yml` is the same one.
const PREFETCH_SEED_DIRECTORY: &str = "fixtures/prefetch";

/// `fuzz_evtx`'s seed corpus, which sits outside `fixtures/parsers/` for the same reason
/// `fixtures/prefetch/` does: the files are vendored from a third-party corpus under its own licence
/// and `REUSE.toml` annotates them where they lie (ADR 0018). The tie to `ci.yml` is the same one.
const EVTX_SEED_DIRECTORY: &str = "fixtures/evtx";

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn parsers_fixture_root() -> PathBuf {
    repository_root().join("fixtures/parsers")
}

/// Every file in one fixture directory as `(file name, bytes)`, sorted by name.
///
/// A directory that cannot be read yields nothing and fails the assertion at the end, which is the
/// drift this file exists to catch. A file that cannot be read becomes empty bytes rather than being
/// skipped, so that it fails its own test loudly instead of disappearing from the set.
///
/// `assert!` rather than `panic!` throughout: these helpers are not `#[test]` functions, and
/// `clippy::panic` is denied outside tests (`clippy.toml`).
fn fixtures_in(artifact: &str) -> Vec<(String, Vec<u8>)> {
    let directory = parsers_fixture_root().join(artifact);

    let mut files = Vec::new();
    for entry in std::fs::read_dir(&directory)
        .into_iter()
        .flatten()
        .flatten()
    {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
        else {
            continue;
        };
        files.push((name, std::fs::read(&path).unwrap_or_default()));
    }
    files.sort_by(|left, right| left.0.cmp(&right.0));

    assert!(
        !files.is_empty(),
        "{} holds no fixtures: the fuzz target seeded from it would start from nothing",
        directory.display()
    );
    files
}

fn fixture(artifact: &str, name: &str) -> Vec<u8> {
    let found = fixtures_in(artifact)
        .into_iter()
        .find(|(found, _)| found == name);
    assert!(
        found.is_some(),
        "fixtures/parsers/{artifact}/{name} is missing"
    );
    found.map(|(_, bytes)| bytes).unwrap_or_default()
}

fn launch_file(bytes: &[u8]) -> pca::PcaFile<pca::PcaLaunchEntry> {
    let parsed = pca::parse_app_launch_dic(bytes);
    assert!(parsed.is_ok(), "expected the file to parse: {parsed:?}");
    parsed.unwrap_or(pca::PcaFile {
        entries: Vec::new(),
        rejected: Vec::new(),
    })
}

/// The seed corpus the CI job passes to libFuzzer is written out as a path in `ci.yml`. Renaming a
/// directory here without renaming it there would leave the job pointing at nothing, and libFuzzer
/// would still exit 0 — a green job that fuzzed no artifact at all. Neither end may move alone.
#[test]
fn the_ci_fuzz_job_seeds_from_these_directories() {
    let workflow = repository_root().join(".github/workflows/ci.yml");
    let text = std::fs::read_to_string(&workflow).unwrap_or_default();
    assert!(!text.is_empty(), "{} is unreadable", workflow.display());
    for artifact in SEEDED_DIRECTORIES {
        let seed_path = format!("fixtures/parsers/{artifact}");
        assert!(
            text.contains(&seed_path),
            "ci.yml does not seed a fuzz target from {seed_path}"
        );
    }
    assert!(
        text.contains(PREFETCH_SEED_DIRECTORY),
        "ci.yml does not seed a fuzz target from {PREFETCH_SEED_DIRECTORY}"
    );
    assert!(
        text.contains(EVTX_SEED_DIRECTORY),
        "ci.yml does not seed a fuzz target from {EVTX_SEED_DIRECTORY}"
    );
}

/// The emptiness check `fixtures_in` makes for the parser fixtures, for the seed corpus that does not
/// go through it. libFuzzer handed a directory with nothing in it still exits 0, so `fuzz_prefetch`
/// would report success having never seen a `.pf` file.
#[test]
fn the_prefetch_seed_directory_holds_prefetch_files() {
    let directory = repository_root().join(PREFETCH_SEED_DIRECTORY);

    let seeds = std::fs::read_dir(&directory)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|entry| entry.path().extension().is_some_and(|kind| kind == "pf"))
        .count();

    assert!(
        seeds > 0,
        "{} holds no .pf files: fuzz_prefetch, seeded from it, would start from nothing",
        directory.display()
    );
}

/// The same emptiness check for `fuzz_evtx`'s seeds, and the parse that says they are still Event Log
/// files rather than bytes with an `.evtx` name. Both vendored fixtures hold 17 records and neither
/// has a damaged chunk in it — the damaged cases are built in `evtx.rs` from these same bytes, because
/// the upstream file that carries one is 1 MB of a real machine's logs
/// (`fixtures/evtx/PROVENANCE.md`).
#[test]
fn every_evtx_fixture_parses_and_seeds_the_fuzz_target() {
    let directory = repository_root().join(EVTX_SEED_DIRECTORY);

    let mut seeds = 0;
    for entry in std::fs::read_dir(&directory)
        .into_iter()
        .flatten()
        .flatten()
    {
        let path = entry.path();
        if path.extension().is_none_or(|kind| kind != "evtx") {
            continue;
        }
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();

        match evtx::records(&std::fs::read(&path).unwrap_or_default()) {
            Ok(file) => {
                assert_eq!(file.records.len(), 17, "{name}");
                assert!(file.rejected.is_empty(), "{name} has a rejected record");
            }
            Err(error) => panic!("{name}: {error}"),
        }
        seeds += 1;
    }

    assert!(
        seeds > 0,
        "{} holds no .evtx files: fuzz_evtx, seeded from it, would start from nothing",
        directory.display()
    );
}

#[test]
fn every_bam_fixture_is_decoded_or_refused_rather_than_panicking() {
    for (name, bytes) in fixtures_in("bam") {
        let parsed = bam::parse_value(&bytes);
        // Only the deliberately short one is an error; every other fixture is a value the parser
        // accepts, including the ones that are not the documented 24-byte shape.
        assert_eq!(parsed.is_ok(), name != "truncated.bin", "{name}");
    }
}

#[test]
fn every_usn_fixture_is_decoded_or_refused_rather_than_panicking() {
    for (name, bytes) in fixtures_in("usn") {
        let parsed = usn::parse_buffer(&bytes);
        if name == "truncated.bin" {
            assert!(parsed.is_err(), "{name}");
            continue;
        }
        let parsed = parsed.unwrap_or_else(|error| panic!("{name}: {error}"));
        let damaged = matches!(
            name.as_str(),
            "record-length-zero.bin" | "record-length-past-end.bin" | "unknown-major-version.bin"
        );
        assert_eq!(parsed.damage.is_some(), damaged, "{name}");
    }
}

#[test]
fn the_usn_fixtures_hold_the_records_their_names_say() {
    assert_eq!(
        usn::parse_buffer(&fixture("usn", "three-version-3-records.bin"))
            .unwrap()
            .records
            .len(),
        3
    );
    assert_eq!(
        usn::parse_buffer(&fixture("usn", "one-version-2-record.bin"))
            .unwrap()
            .records
            .len(),
        1
    );
    let skipped = usn::parse_buffer(&fixture("usn", "version-4-then-version-3.bin")).unwrap();
    assert_eq!((skipped.skipped_version_4, skipped.records.len()), (1, 1));
    assert!(
        usn::parse_buffer(&fixture("usn", "next-usn-only.bin"))
            .unwrap()
            .records
            .is_empty()
    );
}

/// `fuzz_filetime` seeds from the BAM directory, because a BAM value's first eight bytes are exactly
/// the little-endian `FILETIME` it converts. This asserts that they really are, so that the seeds
/// stay meaningful for that target rather than becoming arbitrary bytes with a BAM file name.
#[test]
fn the_bam_fixtures_are_filetime_seeds_too() {
    for (name, bytes) in fixtures_in("bam") {
        let Some(head) = bytes.first_chunk::<8>() else {
            assert_eq!(
                name, "truncated.bin",
                "{name} is too short to hold a FILETIME"
            );
            continue;
        };
        let converted = filetime::to_timestamp(u64::from_le_bytes(*head));
        // `u64::MAX` is the value that once panicked inside jiff (ADR 0013); it must come back as
        // `None` rather than as an instant or an abort.
        assert_eq!(
            converted.is_none(),
            name == "filetime-out-of-range.bin",
            "{name}"
        );
    }
}

#[test]
fn every_pca_app_launch_fixture_is_decoded_or_refused_rather_than_panicking() {
    for (name, bytes) in fixtures_in("pca-app-launch") {
        match pca::parse_app_launch_dic(&bytes) {
            Ok(file) => {
                assert!(!file.entries.is_empty(), "{name} yielded no records");
                assert_eq!(
                    file.rejected.is_empty(),
                    name != "malformed-lines.txt",
                    "{name}"
                );
            }
            // A byte order mark is the one thing that fails a whole file.
            Err(error) => assert_eq!(name, "utf16-bom.txt", "{name}: {error}"),
        }
    }
}

#[test]
fn the_malformed_app_launch_fixture_keeps_the_good_lines_and_accounts_for_the_rest() {
    let file = launch_file(&fixture("pca-app-launch", "malformed-lines.txt"));

    assert_eq!(file.entries.len(), 2);
    assert_eq!(file.entries[0].path, r"C:\Users\alex\first.exe");
    assert_eq!(file.entries[1].path, r"C:\Users\alex\third.exe");
    // Line 2 has no delimiter, line 3 an impossible date, line 4 an empty path; line 5 is blank and
    // is neither a record nor an error, and the numbers are the ones a text editor shows.
    let rejected: Vec<usize> = file
        .rejected
        .iter()
        .map(|rejected| rejected.line_number)
        .collect();
    assert_eq!(rejected, [2, 3, 4]);
}

#[test]
fn the_app_launch_fixture_without_a_trailing_crlf_still_yields_its_last_record() {
    let file = launch_file(&fixture("pca-app-launch", "no-trailing-crlf.txt"));

    assert!(file.rejected.is_empty());
    assert_eq!(file.entries.len(), 2);
    assert_eq!(file.entries[1].path, r"C:\Users\alex\last.exe");
}

#[test]
fn every_pca_general_fixture_is_decoded_rather_than_panicking() {
    for (name, bytes) in fixtures_in("pca-general") {
        match pca::parse_general_db(&bytes) {
            Ok(file) => {
                assert!(!file.entries.is_empty(), "{name} yielded no records");
                assert_eq!(
                    file.rejected.is_empty(),
                    name != "malformed-lines.txt",
                    "{name}"
                );
            }
            Err(error) => panic!("{name}: {error}"),
        }
    }
}

/// The general databases' layout is reverse-engineered, so a line with more or fewer fields than any
/// write-up describes is a newer Windows build and not a broken line.
#[test]
fn the_general_db_fixture_with_varying_field_counts_keeps_every_line_whole() {
    let bytes = fixture("pca-general", "field-count-varies.txt");
    let file = match pca::parse_general_db(&bytes) {
        Ok(file) => file,
        Err(error) => panic!("expected the file to parse: {error}"),
    };

    assert!(file.rejected.is_empty());
    assert_eq!(file.entries.len(), 2);
    assert_eq!(file.entries[0].fields.len(), 7);
    assert_eq!(file.entries[1].fields.len(), 2);
}
