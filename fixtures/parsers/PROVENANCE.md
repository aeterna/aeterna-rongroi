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
| `powershell-text/` | `powershell_text::parse_history`, `powershell_text::classify` | `crates/rongroi-parsers/src/powershell_text.rs`, `tests/fixtures.rs` | `fuzz_powershell_text` |
| `prefetch/` | `prefetch::parse` | `tests/fixtures.rs`, and the `prefetch` collector through `fixtures/hosts/prefetch-fivem-editions` | `fuzz_prefetch`, beside the vendored corpus in `fixtures/prefetch/` |
| `task/` | `task::parse_task` | `crates/rongroi-parsers/src/task.rs`, `tests/fixtures.rs` | `fuzz_task` |
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
| `bam/filetime-2025-12-31T21-30-00.2231407Z.bin`, `bam/filetime-2025-12-31T11-00-00Z.bin`, `bam/filetime-2025-12-31T22-00-00Z.bin` | `documented-24-byte-value.bin` with its `FILETIME` set to the time in the name — the first with a fraction of a second, as Windows writes them — so that the session statement's fixture hosts have BAM ends to compare with (ADR 0062) |
| `pca-app-launch/normal.txt` | Three ordinary CRLF records |
| `pca-app-launch/cp1252-path.txt` | A path with `é` as the single CP-1252 byte Windows stores, not UTF-8 |
| `pca-app-launch/malformed-lines.txt` | Good lines, a line with no delimiter, an impossible date, an empty path and a blank line |
| `pca-app-launch/no-trailing-crlf.txt` | A file that was truncated mid-write, or never got its final CRLF |
| `pca-app-launch/utf16-bom.txt` | UTF-16 with a byte order mark: the one thing that fails a whole file |
| `pca-general/normal.txt` | Two ordinary `\|`-delimited records |
| `pca-general/field-count-varies.txt` | One line with more fields than any write-up describes and one with fewer |
| `pca-general/malformed-lines.txt` | A good line and a line with no delimiter at all |
| `prefetch/v31-raw-FIVEM.EXE-legacy.pf` | An uncompressed SCCA version 31 payload named `FIVEM.EXE`, with two run times, a run count of 12, one invented volume (`\VOLUME{01d00000000000000-0000abcd}`, serial `0000abcd`) and a string table of two entries: `NTDLL.DLL` under `\WINDOWS\SYSTEM32\`, and the executable's own entry below `\USERS\ALEX\APPDATA\LOCAL\FIVEM\FIVEM.APP\`, the folder the measurement of ADR 0062's amendment found Legacy's entry below. The file below that folder is invented. Written from the layout `prefetch-core` reads (header, `FileInformation` at 84 with the count at +124, volume records of 96 bytes), not captured and not compressed, so it exercises no decompression |
| `prefetch/v31-raw-FIVEM.EXE-enhanced.pf` | The same shape with one run time, its own entry below `\USERS\ALEX\APPDATA\LOCAL\FIVEM FOR GTAV ENHANCED\` |
| `prefetch/v31-raw-PLAYGTAV.EXE-neither.pf` | The same shape named `PLAYGTAV.EXE`, its own entry below `\PROGRAM FILES\`, and a second entry, an invented `EXAMPLE.DLL`, below Enhanced's folder: a file whose own entry is below neither folder although another entry is |
| `prefetch/v31-raw-FIVEM.EXE-session-legacy.pf`, `prefetch/v31-raw-FIVEM.EXE-session-enhanced.pf` | `v31-raw-FIVEM.EXE-legacy.pf` and `-enhanced.pf` with one run time each, 2025-12-31T20:00:00Z and 2025-12-31T10:00:00Z, and the other seven cleared: the starts the session statement's fixture hosts compare with (ADR 0062) |
| `powershell-text/history-mixed-crlf.txt` | A PSReadLine history file written by hand: UTF-8 with CRLF lines (no byte-order mark: `check-unicode` refuses one in a text file, and the parser's own test covers it), ordinary commands, a download-then-execute line to a reserved `.invalid` name, a Defender switch and `Clear-History` (ADR 0064). No line was typed on a real machine |
| `powershell-text/history-lf-no-bom.txt` | The same format with LF lines and no byte-order mark; one download-then-execute line to a private address |
| `powershell-text/command-line-encoded.txt` | A Windows PowerShell command line as event 400's `HostApplication` carries one: a hidden window and an `-enc` argument whose UTF-16LE base64 decodes to a download-then-execute line to a `.invalid` name |
| `powershell-text/not-utf8.bin` | Two lines that are not UTF-8, read with replacement characters |
| `task/logon-exec-utf16le.xml` | A task file as the Task Scheduler's own format describes it, written by hand: UTF-16 little-endian with a byte-order mark and CRLF lines, a logon and a calendar trigger, an invented account SID as the principal, and one `Exec` action whose command uses `%LOCALAPPDATA%` and which has an `Arguments` element the parser must never return. Not captured from a machine (ADR 0060) |
| `task/boot-exec-utf8.xml` | A boot-triggered task in UTF-8 with no byte-order mark, running as `S-1-5-18`, with a quoted command |
| `task/disabled-com-handler-utf16le.xml` | A disabled task whose one action is a COM handler, with a WNF state-change trigger |
| `task/not-a-task.xml` | Well-formed XML whose root is not `Task` |
| `task/truncated-utf16le.xml` | The first half of `logon-exec-utf16le.xml`: a file that ends inside an element |
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
