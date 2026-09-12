# ADR 0018 — EVTX parsing

- Status: proposed
- Date: 2026-09-12

## Context

Windows Event Log is the artifact behind M2's tamper signals. **Clearing a log is itself logged** — as
event 1102 on the `Security` channel and 104 on the others — so an Event Log reader is how this tool
can show that the record of what happened was removed, which is a stronger signal than anything the
removed records would have carried.

ADR 0013 built the parsers crate around BAM and PCA because those two need no external crate, and left
Prefetch, EVTX and Amcache to be argued one at a time: "each of those carries a dependency and a
licence question". ADR 0015 made that argument for Prefetch. This is the one for EVTX, and it is the
harder of the two — the dependency is larger, it fails `cargo deny` as it stands, and its test corpus
is the most personal data this repository has been asked to vendor.

## Decision

### A dependency, not our own binary XML decoder

`evtx` 0.12.2 (omerbenamram), `default-features = false`.

An `.evtx` file is not a record format with a header to read. It is a 4 KiB file header, 64 KiB chunks
each carrying their own string table and template cache, and inside each record a **binary XML**
dialect with templates, substitution arrays, per-chunk string interning and typed value variants.
Writing that here would mean writing a template-substituting XML interpreter over attacker-controlled
offsets, in a program whose whole job is to be correct about a hostile input. The `evtx` crate is
`#![forbid(unsafe_code)]`, is on its 0.12 line with a decade of samples behind it, and already
implements the record recovery around damaged chunks that this parser needs. Writing our own to avoid
the dependency would be the larger risk, not the smaller one — the same conclusion ADR 0015 reached
about Xpress-Huffman, reached again on a bigger format.

`default-features = false` drops two default feature groups: `evtx_dump`, the crate's CLI, which would
pull `clap`, `dialoguer`, `indoc`, `simplelog`, `anyhow` and `tempfile` into a library that has no
command line; and `multithreading`, which would pull `rayon` and a global thread pool into a crate
`CONVENTIONS.md` §3 requires to be pure. Without it, chunks are processed in order on the calling
thread, so the order of returned records is deterministic — worth having in a tool whose output a
person is asked to compare.

### The RUSTSEC ignore, and what would end it

**`cargo deny check` fails with this dependency and no ignore entry**, and that is not a surprise to be
worked around silently. `evtx` depends on `encoding` 0.2.33, which carries **RUSTSEC-2021-0153**:
unmaintained, last released 2016-08-28, and the advisory lists no patched version, which cargo-deny
renders as "No safe upgrade is available!". The dependency is **non-optional** — it is a plain entry in
`evtx`'s `[dependencies]` and no feature flag removes it — so the choice is the ignore entry or no
Event Log support.

The entry is in `deny.toml` with its reason written out, and the reason states the exposure instead of
implying there is none:

- **What it is used for.** `encoding` is the ANSI codec that decodes 8-bit strings inside a record's
  binary XML (`ParserSettings::ansi_codec`, Windows-1252 by default).
- **What the exposure actually is.** Those bytes come from the `.evtx` file under examination, which on
  a machine being checked is exactly the input its owner has a motive to craft. A decoding defect in an
  unmaintained crate is therefore reachable from input this program does not control. **That risk is
  real and is accepted, not absent.**
- **What bounds it.** It is an *unmaintained* notice rather than a known vulnerability: no CVE, no
  proof-of-concept, nothing to patch. The crate performs no I/O and opens no socket, so a defect is a
  wrong parse rather than a foothold, in a program that is offline by construction (ADR 0003). And
  `fuzz_evtx` points a coverage-guided fuzzer at the path that reaches it (ADR 0016).
- **What would end it.** `evtx` moving to `encoding_rs`, which is what the advisory names as the
  alternative and what this repository would prefer. The entry is revisited on every `evtx` update, the
  way the six Tauri entries are revisited on every Tauri update.

**The ignore and the dependency are one commit on purpose.** An ignore entry for an advisory that
nothing in the graph triggers is a false claim about the project, and cargo-deny reports it as an
`advisory-not-detected` warning; landing the two apart would put the repository in that state for
however long the gap lasted.

Both halves were run rather than assumed. With the dependency and no entry: `advisories FAILED, bans
ok, licenses ok, sources ok`, exit 1, naming `encoding v0.2.33 └── evtx v0.12.2 └── rongroi-parsers`.
With the entry: `advisories ok, bans ok, licenses ok, sources ok`, exit 0. The entry is load-bearing,
and nothing else in the check moved — `bans`, `licenses` and `sources` pass with the new dependency
tree exactly as they did before it.

### A damaged chunk returns what parsed

`records` returns `EvtxFile { records, rejected }`, the shape `pca::PcaFile` set and ADR 0013 made a
property of this crate. A chunk whose header does not parse is one `RejectedRecord`; the chunks around
it are read normally.

This matters more here than for any other artifact in M2. The reason to read an Event Log at all is
that a log may have been tampered with, and a partially overwritten file is the expected shape of that
— the records that survive are the evidence. A parser that failed the file on one bad chunk would lose
exactly the records worth having, and it would do so on the files that matter most. The behaviour is
tested both ways round: a damaged second chunk, and a damaged first chunk, each costing 17 records and
leaving the other 17.

The one thing that still fails a whole file is a header that does not parse, which is positive evidence
that the bytes are not this artifact — the same line PCA draws at a UTF-16 byte order mark. A file
shorter than the 4 KiB header block is `Truncated` before the dependency is called at all, because the
upstream error type reports "too short" and "not an Event Log" through one variant with one message,
and a caller cannot tell them apart.

### Event-id meaning belongs to a rule, not here

The event id, channel, provider and level are handed back as the file spelled them, with no meaning
attached to any of them — including 1102 and 104, the ids that motivated this parser. A rule file can
be read, reviewed, translated and contradicted by a fixture; a constant inside a decoder cannot. This
is ADR 0002's "evidence, never a verdict" at the level of a single field, and it is the same reasoning
that keeps BAM's undocumented bytes unnamed.

A consequence worth stating: **nothing in this PR detects a cleared log.** The parser makes that rule
possible and does not constitute it.

### The payload is dropped on purpose, which is a departure

ADR 0013 made "nothing read is silently dropped" a property of this crate. This parser keeps a
record's `System` block and **discards the event payload** — `EventData`, `UserData`, and the
`Computer` field every record carries.

It is a departure and it is deliberate. The payload is where the personal data of this artifact lives:
user names, host names, source IP addresses, SIDs and full command lines, with no fixed schema.
`rongroi_core::view` redacts a `path` field because it knows what a path is; it cannot redact an
arbitrary tree of provider-defined elements it has never seen. Keeping the payload would put every one
of those strings one `Debug` away from a report, in a tool whose SS mode exists to promise the
opposite. Nothing that reads this parser needs it: presence, identity and time of a record are what the
M2 signals rest on.

The word that matters is *silently*. The module documentation says what is dropped and why, the struct
carries no half-kept remnant of it, and a later rule that genuinely needs a payload field has to widen
the struct in a PR that can be reviewed on that question alone. The alternative considered and rejected
was keeping the payload as an opaque JSON blob, which would have satisfied the letter of ADR 0013 while
making the privacy problem worse.

### The dependency's error type stops at this module

`EvtxError` appears in no signature outside `evtx.rs` and is not re-exported. The match on it is
exhaustive rather than wildcarded: `EvtxError` is not `#[non_exhaustive]`, so a variant added upstream
becomes a compile error here instead of being silently mislabelled.

**Nothing read from the file reaches `detail`.** This is where that promise is easiest to break, and
the upstream `Display` implementations were read before any of them was forwarded rather than after:
`FailedToParseChunk` prints a chunk number, `FailedToParseRecord` prints a record id, `InvalidDataSize`
prints two sizes from the record, and `CalculationError` prints a message built from the file's own
stream length. None of those is a user name — but `error.rs` says `detail` carries nothing read from
the machine, and a rule with one exception in it is not a rule a reviewer can rely on. Every `detail`
is a fixed sentence.

The chunk number and record id are worth having, so they are kept as **typed fields** of
`RejectedRecord` instead, which is the same answer `pca::RejectedLine` gave for a line number. A test
asserts that no string from either fixture, and no digit at all, appears in a `Malformed` message.

| `EvtxError` | becomes |
|---|---|
| `DeserializationError` at header time | `Malformed { field: "signature" }` |
| `DeserializationError` while reading records | `Malformed { field: "record" }` |
| `FailedToParseChunk` | `Malformed { field: "chunk" }`, with `chunk_number` kept as a field |
| `FailedToParseRecord` | `Malformed { field: "record" }`, with `record_id` kept as a field |
| `InvalidDataSize` | `Malformed { field: "record" }` |
| `CalculationError` | `Malformed { field: "header" }` |
| `SerializationError` | `Malformed { field: "record" }` |
| `FailedToCreateRecordModel` | `Malformed { field: "record" }` |
| `Unimplemented` | `Malformed { field: "record" }` |
| `InputError`, `IoError` | `Malformed { field: "input" }` — unreachable from an in-memory cursor, mapped so the match stays exhaustive |

### The timestamp does not go through `crate::filetime`

Every other parser here converts a raw `FILETIME` through the crate's one tested conversion and keeps
the raw `u64` beside it (ADR 0013). **This one cannot**, and the difference is recorded rather than
hidden: `evtx` converts a record's `FILETIME` internally and hands back an already-converted instant,
so the raw value never reaches this code to be kept or re-converted. A record whose timestamp that
conversion rejects becomes a rejected record rather than a record with no time.

One observable consequence pins which source is in use: `written` carries the record header's full
100-nanosecond resolution (seven fractional digits), while the `SystemTime` attribute the crate renders
into XML is printed with six. The test asserts the seven-digit value, so a change of source fails
rather than passing with a value that looks close enough.

## Fixtures

Two files, 136 KiB, vendored from the `evtx` crate's own Apache-2.0 corpus, which
`docs/research/06-testing-windows-forensic-code.md` already vetted as vendor-eligible. Source, commit,
per-file detail, and what each file was scanned for are in `fixtures/evtx/PROVENANCE.md`.

**This is the highest-PII artifact the repository has vendored, and the selection was the work.** Seven
candidate files of the smallest available size were decoded and read in full. Five were dropped:

- one carrying an Active Directory domain, an account name, an address and a full PowerShell command
  line (and a second file that is byte-for-byte identical to it under another name);
- one carrying three real routable IP addresses and a failed logon against a real host;
- one carrying account names, two machine SIDs and account-creation records;
- one carrying the machine SID of a real computer's built-in Administrator.

They were dropped rather than redacted because **a record is checksummed within its chunk**, so
editing a string breaks the chunk — the same constraint that rules out in-place redaction for Prefetch
— and because `cargo xtask scrub-check`, named in `CONVENTIONS.md` §4, still does not exist. The
choice for each file is to vendor it whole or not at all.

**Reading the decoded text was not optional, and neither was reading the bytes.** The two scans are
blind in opposite directions, and both directions were observed on these files:

- The rejected `HelloForBusiness` sample shows **no SID at all** in a raw scan of its bytes, because
  binary XML stores a SID as 28 binary bytes. Only the decode revealed it. A grep over `.evtx` bytes is
  not a privacy check.
- The kept `languagepacksetup` sample renders `Computer: DESKTOP-1N4R894`, and that string does **not**
  appear in its bytes, because the value is interned in the chunk's string table and substituted into a
  template.
- The kept `application-no-crc32` sample carries, in chunk slack past its last live record, Windows
  Error Reporting paths and a service-hang report id that appear in **no** rendered record. Only the
  raw scan revealed those.

What the two kept files do contain is written down in `PROVENANCE.md` rather than left to be found:
system paths only, the well-known `S-1-5-18` and no other SID, no user name, no address, no credential
material — and a Windows-generated `DESKTOP-XXXXXXXX` computer name in each, which is a host name and
therefore in tension with `CONVENTIONS.md` §4's unconditional wording. That was **not avoidable**:
every `.evtx` record carries a `Computer` field by format, so a file with no host name in it is not an
Event Log. The names are machine-generated and identify nobody, which is why they were accepted; the
same tension is recorded for Prefetch in ADR 0015.

The corrupt-chunk cases are **built in the tests from these bytes** rather than vendored. The upstream
file with a deliberately bad chunk magic is 1 MB of a real machine's logs, against a test helper that
duplicates a known-good chunk and breaks its signature in four lines.

## What is unverified

- **No fixture contains event 1102 or 104**, so the artifact that motivates this parser is not
  exercised by a sample. The corpora that carry those events are real red-team capture (GPL-3.0) and an
  unlicensed collection, and `docs/research/06` ruled both out for vendoring. Nothing in the parser
  depends on the id — it assigns no meaning to any — but the rule that reads one will need a fixture
  this repository does not yet have.
- **No `Security` channel file is vendored**, because every `Security` sample in the corpus carries
  logon records with user names or addresses. The channel is a string to this parser.
- **No file written by Windows 11 was parsed.** The corpus predates it. The format is stable across
  Windows 7 through 11 and this is not expected to matter, but it has not been checked here.
- **The upstream crate's own recovery behaviour is taken as observed, not as specified.** That a
  damaged chunk costs only its own records was established by constructing such a file and running it,
  not from a document.

## Consequences

- `rongroi-parsers` gains two dependencies in its manifest, `evtx` and `serde_json`, and a
  substantially larger transitive tree than any previous parser brought — `sonic-rs`, `bumpalo`,
  `winstructs`, `chrono`, `utf16-simd`, the `encoding-index-*` tables, and `skeptic` as a build
  dependency of `evtx`. `cargo deny check`'s `licenses`, `bans` and `sources` all pass over it
  unchanged; `advisories` passes only because of the entry above.
- **`deny.toml` now carries a non-Tauri ignore**, the first. It is tied to one dependency and one
  upstream decision, and the reason field says what would end it.
- The crate is still pure: no OS call, no `Host`, no clock, no global state. The one entry point in
  `evtx` that touches a filesystem, `EvtxParser::from_path`, is never called — purity here is a
  property of this module's call site rather than of the dependency, which is a weaker guarantee than
  `prefetch-core` gave and is stated as such.
- A sixth fuzz target, `fuzz_evtx`, running in the `fuzz smoke (ubuntu)` job with the other five.
- Nothing consumes this parser yet. The collector that reads `%SystemRoot%\System32\winevt\Logs` —
  which needs an elevated token for the `Security` channel and reports `Unmeasured` without one — and
  the rules that read the result are later PRs. No report changes.
