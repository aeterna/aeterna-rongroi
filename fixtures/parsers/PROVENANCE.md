# Parser fixtures — provenance

Every file in this folder is **synthetic and hand-written**. None was captured from a real machine, so
none contains a real person's user name, host name, SID or files. The user name `alex` and the company
names in them are invented.

These are artifact *bytes*, not fixture hosts: a parser takes `&[u8]` and needs no path, no user and no
registry (ADR 0013), so a fixture here is a file of bytes and nothing else.

## They are read twice

Each directory is both an L0 test input and the **seed corpus of a fuzz target** (ADR 0016). A fixture
added here for a parser test therefore improves the fuzz seeds at the same time, and there is no second,
parallel set of sample bytes to keep in step.

| Directory | Parser | L0 tests | Fuzz target seeded from it |
|---|---|---|---|
| `bam/` | `bam::parse_value` | `crates/rongroi-parsers/src/bam.rs`, `tests/fixtures.rs` | `fuzz_bam`, and `fuzz_filetime` — a BAM value's first eight bytes are the `FILETIME` |
| `pca-app-launch/` | `pca::parse_app_launch_dic` | `crates/rongroi-parsers/src/pca.rs`, `tests/fixtures.rs` | `fuzz_pca_app_launch` |
| `pca-general/` | `pca::parse_general_db` | `tests/fixtures.rs` | `fuzz_pca_general` |
| `usn/` | `usn::parse_buffer` | `crates/rongroi-parsers/src/usn.rs`, `tests/fixtures.rs` | `fuzz_usn` |

## What each file is

| File | What it is |
|---|---|
| `bam/documented-24-byte-value.bin` | The shape the public write-ups describe: `FILETIME` 2020-01-01T00:00:00Z, moderation state 0, twelve trailing bytes with no established meaning |
| `bam/moderation-state-set.bin` | The same, with a non-zero moderation state |
| `bam/timestamp-only.bin` | Eight bytes: the shortest value the parser accepts |
| `bam/epoch-filetime.bin` | A `FILETIME` of zero — 1601-01-01, which is also what an unfilled field looks like |
| `bam/longer-than-documented.bin` | Longer than 24 bytes, as a newer Windows build might write |
| `bam/filetime-out-of-range.bin` | `FILETIME` `u64::MAX`: the value that once panicked inside jiff (ADR 0013) |
| `bam/truncated.bin` | Seven bytes — one short of a timestamp, so a `Truncated` error |
| `pca-app-launch/normal.txt` | Three ordinary CRLF records |
| `pca-app-launch/cp1252-path.txt` | A path with `é` as the single CP-1252 byte Windows stores, not UTF-8 |
| `pca-app-launch/malformed-lines.txt` | Good lines, a line with no delimiter, an impossible date, an empty path and a blank line |
| `pca-app-launch/no-trailing-crlf.txt` | A file that was truncated mid-write, or never got its final CRLF |
| `pca-app-launch/utf16-bom.txt` | UTF-16 with a byte order mark: the one thing that fails a whole file |
| `pca-general/normal.txt` | Two ordinary `\|`-delimited records |
| `pca-general/field-count-varies.txt` | One line with more fields than any write-up describes and one with fewer |
| `pca-general/malformed-lines.txt` | A good line and a line with no delimiter at all |
| `usn/three-version-3-records.bin` | A buffer as `FSCTL_READ_USN_JOURNAL` returns it: next USN 9000, then three 80-byte `USN_RECORD_V3` records named `ab`, two under one parent and one under another, with a create, a close with data extended, and a close with a delete. Written from Microsoft's documented layout (ADR 0047), not captured |
| `usn/one-version-2-record.bin` | One 64-byte `USN_RECORD_V2` record, whose parent is a 64-bit index |
| `usn/version-4-then-version-3.bin` | A version 4 record's header, which is skipped, then a version 3 record |
| `usn/next-usn-only.bin` | Eight bytes: the next USN and no record, which is what a read at the end of the journal returns |
| `usn/record-length-zero.bin` | A good record, then one whose `RecordLength` is 0 — the value Microsoft's sample loop never advances past |
| `usn/record-length-past-end.bin` | A good record, then one claiming 4000 bytes in an 80-byte remainder |
| `usn/unknown-major-version.bin` | A record with major version 5, which stops the buffer |
| `usn/truncated.bin` | Seven bytes — one short of the next USN, so a `Truncated` error |

Line endings matter here — CRLF is what Windows writes — so `.gitattributes` marks this folder binary
and git does not normalise it.

When a fixture is generated from a real Windows install, record here: what generated it, the Windows
build, that networking was disabled, and who checked it for a real user name, host name or SID, and how.
Neither `tools/fixture-gen/` nor `cargo xtask scrub-check` exists — ADR 0016 counts both among the promises
this repository has made with no code behind them, and `CONVENTIONS.md` §4 records the gap — so that last
check is a person's. Never copy files from a real player's PC into this repository.
