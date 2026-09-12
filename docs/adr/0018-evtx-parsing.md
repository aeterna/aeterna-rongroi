# ADR 0018 — EVTX parsing

- Status: accepted
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
`#![forbid(unsafe_code)]`, is on its 0.12 line with a sample corpus going back to 2018, and already
implements the record recovery around damaged chunks that this parser needs. Writing our own to avoid
the dependency would be the larger risk, not the smaller one — the same conclusion ADR 0015 reached
about Xpress-Huffman, reached again on a bigger format.

`default-features = false` drops two default feature groups: `evtx_dump`, the crate's CLI, which would
pull `clap`, `dialoguer`, `indoc`, `simplelog`, `anyhow` and `tempfile` into a library that has no
command line; and `multithreading`, which would pull `rayon` and a global thread pool into a crate
`CONVENTIONS.md` §3 requires to be pure. Without it, chunks are processed in order on the calling
thread, so the order of returned records is deterministic — worth having in a tool whose output a
person is asked to compare.

### Vendored and patched, not taken from the registry

`third_party/evtx/`, wired in by `[patch.crates-io]` in both the root `Cargo.toml` and `fuzz/Cargo.toml`.

`fuzz_evtx` found this before the branch was pushed. `binxml::tokens::read_template_values_cursor`
reads `number_of_substitutions`, a `u32`, from the record and passed it straight to
`Vec::with_capacity` — twice — with nothing bounding it against the bytes remaining. A 69 632-byte
file, the smallest an `.evtx` comes in, reaches:

```
==20889== ERROR: libFuzzer: out-of-memory (malloc(7717636096))
    #9  evtx::binxml::tokens::read_template_values_cursor
    #12 rongroi_parsers::evtx::records
```

7.7 GB. On macOS the reservation is lazy and the process survives — that part is measured, on this
machine, by the run quoted above.

**The Windows half is reasoned, not observed.** Windows charges a commit up front instead of
overcommitting, and a Rust allocation that fails calls `handle_alloc_error`, which aborts: not an `Err`,
not `catch_unwind`-able, and it takes the process with it. So a Windows machine without 7.7 GB of commit
available loses the process, while one with a large enough page file may simply succeed. This was not run
on Windows. What *is* certain either way is that the size is chosen by the file rather than by the
program, and `crates/rongroi-parsers/src/lib.rs` promises a parser never panics and never aborts on any
input — a promise that cannot be kept while an attacker picks the allocation size.

Four options were weighed:

| Option | Why not |
|---|---|
| Bound it from our side, before calling in | The count sits inside each record's binary XML, not in a header. Checking it first means walking binary XML ourselves — writing the decoder this ADR declined to write |
| A git fork via `[patch]` | `deny.toml` sets `unknown-git = "deny"`. A git source is exactly what that line exists to refuse |
| Hold EVTX until upstream releases a fix | Puts M2's tamper signals behind someone else's release schedule, for a two-line change |
| Land it with `fuzz_evtx` excluded | Ships a known abort **and** removes the gate that caught it. The RUSTSEC reason below names this target as something that bounds the dependency's risk; deleting it would hollow out that argument |

So: vendor, bound, upstream, delete when released. The upstream half is done —
[omerbenamram/evtx#294](https://github.com/omerbenamram/evtx/pull/294), both patches, 2026-09-12 — and
it credits the April 2026 reports (#291, #292, #293) instead of presenting the finding as new, because
it is not.

Whether it lands is outside our control, and the evidence points both ways: the maintainer has merged
three fixes of exactly this class and shipped a `### Security`-labelled hardening in 0.12.2, but he also
closed #293 as an AI-generated report and no outside contributor has landed an allocation-bounds change.
If it is declined or goes unanswered, `third_party/evtx/` stops being temporary, and that is the point
at which a RustSec informational advisory becomes the reasonable next step rather than the rude one. `sources ok` from `cargo deny` was verified with the
path source in place — a path inside the repository is reviewable in the same pull request as the code
that uses it, which is what `unknown-git = "deny"` is protecting against in the first place.

The patch is two changes, and both follow an idiom the crate already uses — in
`src/utils/byte_cursor.rs`, `read_sid_ref` and `read_sized_slice_aligned_in` each check the bytes
remaining before allocating. (They are in the cursor's own module, not in `tokens.rs` beside the
defect; a reviewer told to look in "the same file" would not find them.) The descriptor loop
consumes exactly four bytes per entry, so the reservation is capped at `bytes_remaining / 4`; the second
allocation reserves `value_descriptors.len()`, which is known exactly by then. **What is reserved
changes; what is accepted does not** — a truncated file still fails in the same loop with the same
error. The bound is *sound* on any buffer — it never exceeds what the input could hold — but its
*tightness* rests on the buffer being one 64 KiB chunk, which `EvtxParser` guarantees and the crate's
public API does not (`EvtxChunkData::new` takes a `Vec` of any length). So it is stated as "the bytes
remaining" and never as a fixed 16 384.

Every other `with_capacity` in the crate was checked. None is sized by an unchecked value from the
file: they are bounded by `EVTX_CHUNK_SIZE`, by a slice already in memory, by a `u16` field, by an
explicit bounds check three lines earlier (`ir.rs`'s template `data_size`), or they sit in the
`wevt_templates` feature, which is off.

**A second patch followed, and how it arrived matters more than what it fixes.** `binxml/name.rs:78`
evaluates `len * 2` in `u16` before widening, where `len` is a name length read from the file, so any
length above 32767 overflows: a panic where overflow checks are on, and a silent wrap in an ordinary
release build, which leaves the cursor in the wrong place with nothing reporting it. The fix widens
first.

`fuzz_evtx` found it **on `dev`, minutes after the pull request carrying the first patch had merged
with that same job green**. Nothing had changed between the two runs except libFuzzer's seed. This is
§8.3 of the workspace standard happening in front of us rather than in the abstract: a green run is
evidence about one execution, not about a commit, and it was right to re-read CI on `dev` instead of
carrying the branch's result forward. The regression test for this one is therefore deterministic —
built in `evtx.rs` from the good fixture, the way the damaged-chunk cases are — rather than a saved
crash input and a hope that the fuzzer finds it again.

`third_party/evtx/` is excluded from the workspace, from `typos`, and from this project's lints, and
`REUSE.toml` annotates it under **upstream's** licence rather than ours. It is Omer Ben-Amram's code; a
`diff -r` against the published tarball must show `src/binxml/tokens.rs` and nothing else, and
`third_party/evtx/PROVENANCE.md` gives the command.

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

One file, 68 KiB, vendored from the `evtx` crate's own Apache-2.0 corpus, which
`docs/research/06-testing-windows-forensic-code.md` already vetted as vendor-eligible. Source, commit,
detail, and what it was scanned for are in `fixtures/evtx/PROVENANCE.md`.

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
- The since-removed `application-no-crc32` sample carried, in chunk slack past its last live record,
  Windows Error Reporting paths and a service-hang report id that appeared in **no** rendered record.
  Only the raw scan revealed those.

**A sixth file was removed after it had been vendored and committed.** `application-no-crc32.evtx` was
accepted on a byte scan that missed a real machine SID — `S-1-5-21-…-1000`, the first user account of a
real computer — held as UTF-16 in its chunk string table. The provenance document written alongside it
asserted that no such SID was present, and was wrong in both directions: the machine SID was there, and
the well-known `S-1-5-18` it did claim was not. The branch had not been pushed. The file is gone, the
correction is recorded in `fixtures/evtx/PROVENANCE.md` rather than quietly applied, and the standard is
now that such a claim is a counted measurement with the counts written down.

That leaves one sample, and the cost is named in "What is unverified" below rather than absorbed
silently.

What the kept file does contain is written down in `PROVENANCE.md` rather than left to be found: system
paths only, no SID in any form, no user name, no address, no credential material — and a
Windows-generated `DESKTOP-XXXXXXXX` computer name, which is a host name and therefore in tension with
`CONVENTIONS.md` §4's unconditional wording. That was **not avoidable**: every `.evtx` record carries a
`Computer` field by format, so a file with no host name in it is not an Event Log. The name is
machine-generated and identifies nobody, which is why it was accepted; the same tension is recorded for
Prefetch in ADR 0015.

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
- **One sample, not two.** Every Event Log test reads `languagepacksetup-operational.evtx` or bytes
  built from it, so a defect peculiar to that file has no second opinion. The `EventID`-as-object shape
  it does not contain is covered by a unit test over `scalar`/`number` rather than by a sample.
- **A third defect is open: a parse that does not terminate.** A crafted input makes `records` never
  return — past 300 s under the sanitizer, past 600 s without it — with and without both patches, so
  it is upstream's and independent of them. Its location is unknown. It makes `docs/testing.md`'s
  "never panic, abort or hang" false for EVTX today, and that document now says so. Two of the three
  defects in this dependency are fixed; the count is going up rather than down, which is itself worth
  weighing the next time a parser this size is taken on.
- **The patch is verified against this repository's use, not against every use of the crate.** The
  bound was exercised by the full test suite, by the reverted-and-restored reproduction, and by a
  263 568-run campaign that found nothing further. Upstream may hold a different view of it, and until
  they take it the vendored copy is ours to maintain.
- **Whether the removed fixture's SID reached a rendered record was never established.** The file was
  removed rather than analysed further; the parser keeps six fields and `UserID` is not among them, but
  that was not the reason for the decision and is not offered as one.

## Consequences

- `rongroi-parsers` gains two dependencies in its manifest, `evtx` and `serde_json`, and a
  substantially larger transitive tree than any previous parser brought — `sonic-rs`, `bumpalo`,
  `winstructs`, `chrono`, `utf16-simd` and the `encoding-index-*` tables. (An earlier draft named
  `skeptic` here as a build dependency of `evtx`: true of the registry crate, not of the vendored one,
  whose manifest drops `[build-dependencies]`. It is in no lockfile in this repository.)
  `cargo deny check`'s `licenses`, `bans` and `sources` all pass over it
  unchanged; `advisories` passes only because of the entry above.
- **`deny.toml` now carries a non-Tauri ignore**, the first. It is tied to one dependency and one
  upstream decision, and the reason field says what would end it.
- **A `third_party/` directory exists for the first time**, with 13 268 lines of someone else's code in
  it, held apart from this project's formatter, lints, spell-check and licence header. That is a
  standing cost: every `evtx` upgrade is now a re-vendor and a re-verify rather than a version bump.
  It is accepted only because it is temporary and because the alternative was shipping a known abort.
- The crate is still pure: no OS call, no `Host`, no clock, no global state. The one entry point in
  `evtx` that touches a filesystem, `EvtxParser::from_path`, is never called — purity here is a
  property of this module's call site rather than of the dependency, which is a weaker guarantee than
  `prefetch-core` gave and is stated as such.
- A sixth fuzz target, `fuzz_evtx`, running in the `fuzz smoke (ubuntu)` job with the other five.
- Nothing consumes this parser yet. The collector that reads `%SystemRoot%\System32\winevt\Logs` —
  which needs an elevated token for the `Security` channel and reports `Unmeasured` without one — and
  the rules that read the result are later PRs. No report changes.
