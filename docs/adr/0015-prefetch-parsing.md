# ADR 0015 — Prefetch parsing

- Status: proposed
- Date: 2026-09-12

## Context

Prefetch is the strongest execution artifact M2 reads: `%SystemRoot%\Prefetch\<NAME>-<HASH>.pf` records
that a program ran, how many times, when it last ran, and which files it loaded. ADR 0013 built the
parsers crate around BAM and PCA precisely because those two need no external crate, and left Prefetch,
EVTX and Amcache to be argued one at a time — "each of those carries a dependency and a licence
question". This is that argument for Prefetch.

A Windows 10 or 11 `.pf` is wrapped in a `MAM\x04` header and compressed with Xpress-Huffman
([MS-XCA] §2.2.4); under it is the classic `SCCA` structure. So the choice is between writing an
Xpress-Huffman decompressor and an SCCA reader in this repository, or taking a dependency.

## Decision

### A dependency, not our own decompressor

`prefetch-core` 0.1.1, Apache-2.0, which is already on `deny.toml`'s allow-list.

What the choice rests on was read from the crate's own source in the local registry, not from its
README or its crates.io page:

| Property | How it was established |
|---|---|
| One dependency, `xpress-huffman`, and nothing else | its `Cargo.toml` |
| Three public functions, all pure — `decompress`, `parse`, `parse_decompressed` | `src/lib.rs`, 430 lines in one file |
| Cannot touch a filesystem | no `std::fs`, `std::path`, `Path::new` or `File::open` anywhere in its source |
| `#![forbid(unsafe_code)]` | first lines of `src/lib.rs` |
| Its readers do not panic on short input | `rd_u32`, `rd_i64`, `rd_utf16_z` all return `Option` |
| Licence and advisories in this workspace | `cargo deny check` on this branch, not on a scratch project |

An Xpress-Huffman decoder is a Huffman-tree build plus a back-reference loop over attacker-controlled
bits, in a program whose entire job is to be correct about a hostile input. Writing that ourselves to
avoid one small, pure, permissively licensed dependency would be the larger risk, not the smaller one.

### The counterweight, stated rather than omitted

`prefetch-core` was first published about two months ago, has one maintainer and few users. That is
exactly the property ADR 0005 weighted heavily when this project chose its YAML crate — "actively
maintained… stable 1.x" — and `prefetch-core` cannot demonstrate it yet.

Two things make the risk acceptable rather than ignored, and neither is an argument that the risk is
absent:

- Its blast radius is a wrong parse, not memory corruption: it is pure, `unsafe`-free, and reaches no
  file, socket or clock. A defect in it produces wrong evidence, which this project's own rule —
  evidence, never a verdict (ADR 0002) — leaves a human reading the report able to question.
- A fuzz target pointed at `prefetch::parse` is what would find such a defect. **That target exists**:
  `fuzz_prefetch`, added once this parser and the fuzz layer were both on `dev` (see Consequences).

### Dependency form: crates.io, locked, not vendored

A plain `crates.io` dependency declared in `[workspace.dependencies]`, like every other dependency
here, with `Cargo.lock` committed and CI running `--locked`.

Not a git source: `deny.toml` sets `[sources] unknown-git = "deny"`, so that would need a policy
change. Not vendored: vendoring means carrying someone else's code in-tree with no automatic security
updates, and the argument for it — patching instantly after a fuzz finding — is weak when the finding
would come from our own fuzz target and a patch release is the normal answer.

### SCCA versions 30 and 31, confirmed in the source

The crate's published description claims v30 and v31. Read in the source rather than taken from the
description: `parse_decompressed` reads the version as a `u32` from offset 0 and returns
`UnsupportedVersion` for anything that is not 30 or 31, and the crate's own constants document the
version values as 17 (XP), 23 (Vista/7), 26 (8.1), 30 (Windows 10), 31 (Windows 11). That range is
exactly what this project supports — Windows 10 22H2 and Windows 11.

An older or unrecognised version is a typed `ParseError::Malformed { field: "scca_version" }`. It is
never a panic and never a silently wrong parse: the older `FileInformation` block has a different
layout, and reading it with v30 offsets would produce plausible, wrong evidence — the worst outcome
available to a tool that is asked to be believed. **A `.pf` from an unsupported version is a
legitimate input, not a defect**, and a collector should treat it as something it could not measure.

**Unverified: no Windows 11 (v31) file was parsed.** The vendored corpus predates Windows 11 and
contains none, and this repository has no Windows 11 machine to produce one. v31 support rests on the
crate's version check accepting 31 and on v30 and v31 sharing a layout, which nothing here confirms.
That is the first thing to check when a real Windows 11 `.pf` is available.

### The third-party error type stops at this module

`PrefetchError` appears in no signature outside `prefetch.rs`, and is not re-exported. `parse` takes
`&[u8]` and returns this crate's `PrefetchRecord` and `ParseError`, the same shape BAM and PCA already
hold (ADR 0013). The rest of the codebase does not learn the name of a third-party type, and replacing
the decompressor later is a change to one file.

| `PrefetchError` | becomes |
|---|---|
| `TooShort` | `Truncated { expected, found }` — 8 and the file's length for a bad container, 84 and the payload's length for a short payload |
| `BadSignature` | `Malformed { field: "signature" }` |
| `Decompress(_)` | `Malformed { field: "compressed_payload" }` |
| `UnsupportedVersion(_)` | `Malformed { field: "scca_version" }` |
| `TruncatedRecord` | `Malformed { field: "record" }` |

The match is exhaustive rather than wildcarded. `PrefetchError` is not `#[non_exhaustive]`, so a
variant added upstream becomes a compile error here instead of being silently mislabelled — the same
reasoning ADR 0013 applied to `ParseError` itself.

**Nothing read from the file reaches `detail`.** `error.rs` promises an error message is safe to show
in either mode, and a `.pf` file's strings are real user paths: its string table holds the full path of
every file the program loaded, which on a real machine includes paths under a user's profile.

The obvious way to get this wrong is to forward the third-party message. Worth recording, because it
inverts the expected finding: **`PrefetchError` implements no `Display` at all** — it derives only
`Debug`, `PartialEq` and `Eq`, and does not implement `std::error::Error`. There is no message to
forward; `{}` on it does not compile. Two things follow. `Debug` is the only rendering available, and
`UnsupportedVersion(u32)` renders the version read from the file, so `{error:?}` is not a safe
shortcut. And the inner `xpress_huffman::Error` does have a `Display`, whose three arms today are
fixed strings with no file content — but forwarding it would make this crate's promise depend on
another crate's future wording, so it is dropped too.

Every `detail` is therefore a fixed sentence, including the version case: the version number is not
quoted, even though a number is not a path, because the rule `error.rs` states is that `detail`
carries nothing read from the machine, and a rule with one exception in it is not a rule a reviewer
can rely on. The cost is real and is accepted: a caller that wants to know *which* version it saw must
look at the bytes, because the error does not say. A test asserts the fixtures' own strings never
appear in an error message.

### A declared size is reserved before it is decoded, so it is capped first

`xpress_huffman::decompress` begins `Vec::with_capacity(decompressed_size)`, where that size is the
`u32` the MAM header declares — read from the file, before a single byte is decoded. A corrupt or
hostile header declaring `u32::MAX` would therefore reserve 4 GiB. An allocation failure aborts the
process; it is not a `Result` any caller can handle, and this crate promises never to abort on any
input.

`parse` therefore refuses a declared size above 16 MiB before calling the decompressor. The limit is
far above anything real — the largest file in the upstream corpus declares 372 KiB — and far below a
size that could hurt. An uncompressed file declares no size and is unaffected, and the check tests for
the `SCCA` signature first, in the same order the decompressor does, so the two cannot disagree about
which shape a file is.

### Decompression and parsing are called as two steps

`prefetch_core::parse` does both in one call. `parse` here calls `decompress` and then
`parse_decompressed`, so that a `Truncated` error can report the length that was actually too short —
the file's for a bad container, the decompressed payload's for a payload that is too short to hold an
SCCA header. Through the one-call form, both cases would report the file's length, which for a
compressed file is not the length that failed.

### What this parser cannot keep

BAM hands back every byte it did not decode (`BamEntry::unparsed_tail`), and ADR 0013 made that a
property of the crate: "Nothing read is silently dropped."

**This module cannot hold that line in full, and says so rather than implying otherwise.**
`prefetch-core` returns a fixed set of fields, so the parts of the SCCA payload it does not expose —
the header past the executable name, the file-metrics array, the directory strings — never reach this
code to be kept. Raw `FILETIME` values are kept beside their converted timestamps, as BAM does, which
is the part of the promise this module does control. Recovering the rest would mean parsing SCCA here
as well as decompressing, which is the work this ADR decided not to do.

### Timestamps go through the existing conversion

Every `FILETIME` — the run times and each volume's creation time — goes through
`filetime::to_timestamp`, the function ADR 0013 put in one place after finding that `jiff` panics in a
debug build on `u64::MAX`. No `FILETIME` is converted a second way in this module. `prefetch-core`
types a `FILETIME` as `i64`; the bits are kept (`cast_unsigned`) rather than clamped, so a value the
conversion cannot represent is `None` with the raw bits still visible, exactly as in `BamEntry`.

## Fixtures

The fixtures are five files vendored from [EricZimmerman/Prefetch](https://github.com/EricZimmerman/Prefetch),
MIT, which `docs/research/06-testing-windows-forensic-code.md` already vetted as vendor-eligible. The
source, commit, licence and per-file detail are recorded in `fixtures/prefetch/PROVENANCE.md`.

**No `.pf` file was captured from a machine belonging to this project or to a player, and none may be.**
A real one's string table contains `\USERS\<name>\…` paths repeated once per referenced file, this is a
public repository, and there is no scrubbing tool in it — `cargo xtask scrub-check` is named in
`CONVENTIONS.md` §4 but does not exist.

**The Windows 10 fixture nevertheless contains user profile paths, and that was a decision rather than
an oversight.** Scanning the corpus decompressed showed that all six of its SCCA v30 files list
`\VOLUME{…}\USERS\<account>\APPDATA\LOCAL\…`, where the account is a single letter belonging to the
upstream author, and that no other folder in the corpus holds a v30 or v31 file. So the choice was
between that file and having no fixture that exercises real MAM/Xpress-Huffman decompression — the one
thing this dependency exists to do. It was kept because the corpus is MIT-licensed and has been public
since 2016, so vendoring publishes nothing that was not already published.

It sits in tension with `CONVENTIONS.md` §4's unconditional "test fixtures never contain a real
person's user name", which is why it is written down in the ADR and in
`fixtures/prefetch/PROVENANCE.md` instead of being left to be discovered. Reversing it costs the
decompression coverage: a synthetic v30 payload built in the test would carry no account name and
would also exercise none of the decompressor. The four older-version fixtures were chosen from the
files that carry system paths only.

The corpus's own coverage decided which files: versions 17, 23 and 26 exercise the unsupported-version
path, the Windows 10 file is the only compressed one and the only version this parser reads, and
`notAPrefetch.pf` is the corpus's deliberately bad file. The remaining corrupt cases — a truncated MAM
header, an implausible declared size, a payload truncated after decompression, a corrupt compressed
stream, a zero-length file, and every prefix of a real file — are constructed in the tests from those
same bytes.

## Consequences

- Two crates enter `Cargo.lock`: `prefetch-core` 0.1.1 and `xpress-huffman` 0.1.3, both Apache-2.0,
  both already permitted by `deny.toml`'s allow-list. No policy change.
- `rongroi-parsers` now has three dependencies. It is still pure, still compiles and tests on macOS and
  Linux, and still has no `Host`, no clock and no OS call.
- **A `fuzz_prefetch` target was owed, and now exists.** `fuzz/` did not exist on this branch; a
  parallel PR added that layer (ADR 0016), and pointing a target at `prefetch::parse` was the one-file
  follow-up once both had landed. It seeds from `fixtures/prefetch/` and runs in the `fuzz smoke
  (ubuntu)` job with the other four. The argument above — that this dependency's immaturity is
  acceptable rather than absent — rests on it, so it is no longer a forward reference.
- Nothing consumes this parser yet. The collector that reads `%SystemRoot%\Prefetch` — which needs an
  elevated token, and reports `Unmeasured` without one — and the rules that read the result are later
  PRs. No report changes.
- Windows 11 v31 output has not been observed. See the unverified note above.
