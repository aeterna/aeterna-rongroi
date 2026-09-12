# ADR 0013 — The parsers crate

- Status: accepted
- Date: 2026-09-12

## Context

M2 adds four Windows artifacts — BAM, PCA, Prefetch and EVTX — and each of them is a byte format
that has to be decoded before anything can be said about it. USN and Amcache belong to M3 (README's
Status table) and will need the same decoding when they come. Where that decoding lives decides what
can be tested, on which machines, and how much of the program has to be trusted to be correct about a
hostile input.

Decoding could have gone inside each collector, next to the code that reads the machine. Every
collector would then mix two different kinds of work: reading a real Windows registry or file, which
only runs on Windows and only with the right privileges, and interpreting bytes, which is pure
arithmetic. The interpretation would be reachable in a test only through a `Host`, on Windows, and
fuzzing it would mean fuzzing the file system with it. Adding a new kind of source is an ADR
(`CONVENTIONS.md` §8), and a new crate in the dependency graph is that kind of change.

## Decision

### A separate, pure crate

`rongroi-parsers` holds the decoders. Every public function takes `&[u8]` and returns
`Result<T, ParseError>`. No OS calls, no paths, no registry keys, no `Host`, no clock, no global
state, and no panic on any input — `unwrap`, `expect`, `panic!` and out-of-bounds indexing are denied
at workspace level, so a malformed artifact is a typed error rather than an abort.

The structs know nothing about `rongroi_core::model`. Turning a parsed struct into an `Observation`,
deciding that an absent artifact is `Unmeasured` rather than empty, and redacting a path for SS mode
all stay in the collector above. Keeping that seam is the point of the separate crate rather than a
side effect of it: the parser layer has no way to reach the evidence model, so it cannot quietly
start making judgements that belong to a rule.

What this buys is concrete. The whole crate compiles, tests and fuzzes on macOS and Linux as well as
Windows, which is what `docs/testing.md`'s L0 row requires, and a fuzz target added later needs no
host, no fixture and no privileges — it needs a byte array.

### BAM and PCA first

These two are the only artifacts in M2 that need no external crate. Prefetch needs decompression,
EVTX needs a binary-XML implementation, and Amcache needs a registry-hive reader; each of those
carries a dependency and a licence question. Doing BAM and PCA first settles the crate's shape — the
error type, the module layout, what the tests look like — without settling a dependency argument at
the same time, and leaves the four harder artifacts to be argued one at a time against a shape that
already exists.

### `ParseError`: two variants, and exhaustive on purpose

`Truncated { expected, found }` and `Malformed { field, detail }` are the two ways bytes fail: there
were not enough of them, or the ones present do not mean what the format says. `field` is a short
fixed identifier (`"timestamp"`, `"delimiter"`, `"encoding"`) so a caller can match on it, and
`detail` never contains anything read from the machine, so an error message is safe to show in either
mode. Nothing wraps `io::Error`: no I/O happens here.

The enum is deliberately not `#[non_exhaustive]`. Every caller is inside this workspace, so when a
later parser needs a third variant, the compiler pointing at each `match` that must now handle it is
the useful outcome rather than friction to be silenced with a wildcard arm. The five parsers still to
come are expected to need a bad-signature or unsupported-version case; that is an added variant and a
compiler error at each call site, which is the review we want.

### Decision: the FILETIME is converted here

The brief left open whether BAM's `last_run` is the raw `u64` or a converted timestamp. It is
converted here, in `filetime::to_timestamp`, and the raw `u64` is kept beside it in
`BamEntry::last_run_filetime`.

The epoch arithmetic is easy to get wrong and there will be at least three callers of it: BAM stores
a `FILETIME`, and so do Prefetch and Amcache. One tested function is better than the same constant
retyped in three collectors. `jiff` is already a workspace dependency used by the CLI, xtask and the
desktop app, so this adds nothing to the lockfile and no new licence question, and it produces the
UTC type the reports already require (`CONVENTIONS.md` §2).

Writing that conversion found a defect that the raw-`u64` option would have pushed into every caller
instead. `jiff::Timestamp::from_nanosecond` returns a `Result`, but reaching it with a `FILETIME` of
`u64::MAX` panics before it can return one: jiff-core checks only that the derived seconds fit in an
`i64` and then calls `new_unchecked`, whose debug assertion fires. Reading that function shows the
release path has no range check at all, so the same input would have produced a wrong instant rather
than an error — in a program whose entire job is to show a reviewer something true. The range is now
checked against jiff's own `MIN` and `MAX` constants before any value is handed over, and the tests
pass in both debug and release. This is the argument for converting in one place stated as evidence:
a defect found once here would otherwise have been three chances to get it wrong quietly.

Keeping the raw `u64` alongside settles the rest. A value that cannot be represented is `None` and
the bytes are still there to look at, and a `FILETIME` of zero converts to 1601-01-01T00:00:00Z
rather than becoming an absence — whether a zero means "never ran" is a judgement for a collector and
a rule, which they cannot make if the parser has already thrown it away.

### Decision: a partly-bad PCA file returns what parsed and accounts for the rest

The brief left open how to represent a file with a malformed line. Both PCA functions return
`PcaFile<T> { entries, rejected }`, where `rejected` holds a `RejectedLine { line_number, reason,
text }` for each line that did not parse.

The alternatives were failing the file on one bad line, which loses good evidence exactly when a
tampered or truncated artifact makes the surviving lines matter most, and returning only a count of
rejects, which says how much was lost but not what or why. A per-line `Result` in one `Vec` was the
closest rival; it was rejected because the common case — read the entries — would then carry the
error handling of the rare case through every caller, and because `rejected.is_empty()` is the plain
way to ask whether a file was intact. A caller that looks only at `entries` sees a shorter file, not
a damaged one, so the two travel together in one struct rather than the failures being dropped.

`line_number` counts every line including blank ones, so it means the same thing as the number a text
editor shows. `text` is the decoded line, which normally contains a full user path: it is here so a
person can see what could not be read, and the doc comment says that a collector putting it in a
report must redact it through `rongroi_core::view` exactly like an observation's `path` field. A
collector that reports only `line_number` and `reason` carries nothing personal at all, and that is
the expected use.

One thing still fails a whole file: a UTF-16 byte order mark. That is positive evidence the bytes are
not this artifact, so nothing in them was readable and saying so once is more use to a collector than
several hundred identical rejections. Without a mark there is no such evidence, and the file is read
as asked and its lines fail one at a time — a real CP-1252 file carrying a few stray NUL bytes from a
truncated write must not be thrown away on a guess about its encoding.

### CP-1252 by table, not by dependency

PCA writes ANSI text. Only 0x80–0x9F needs a table, of 32 entries; 0x00–0x7F is ASCII and 0xA0–0xFF is
Latin-1, where the code point is the byte. That is smaller than taking on `encoding_rs` and keeps the
crate at one dependency. Having written it, the conclusion holds: the module is a table, two short
functions and a test that walks all 256 byte values.

The five positions Microsoft leaves undefined (0x81, 0x8D, 0x8F, 0x90, 0x9D) decode to the C1 control
characters of the same value, which is what the WHATWG encoding standard specifies and what browsers
do. A replacement character would destroy a byte, and this crate does not drop what it was given.

### Bytes with no established meaning are kept and not named

BAM's bytes 12..24 are documented by no public source found. They are kept verbatim in
`BamEntry::unparsed_tail` and given no name, no field split and no interpretation, and the tail
starts wherever decoding actually stopped, so a value that ends between the two known fields keeps
its leftover bytes too. `PcaGeneralEntry::fields` is the same decision in the same crate: the fields
are handed back in order and no position is given a meaning.

The reason is the same in both places and it is the project's own rule stated at the byte level.
This tool shows evidence and never a verdict (ADR 0002); a field named on a guess is a verdict about
what a byte means, dressed as data, and a server admin reading the report has no way to tell the two
apart. Keeping the bytes also means a later Windows build can be understood from data this tool
already collects, and that a value which is not the documented shape can be shown as what it was
rather than silently trimmed to fit.

## What is unverified

**BAM's 24-byte layout is not confirmed on any current Windows build.** The layout used here —
`FILETIME` at 0..8, a power-throttling DWORD at 8..12, twelve undocumented bytes after that — rests on
two independent public write-ups, and **both tested only Windows 10 builds 18363 and 19592, from
2019–2020**. Nothing establishes that it is unchanged on Windows 11, this PR did not re-verify it,
and this repository has no corpus to check it against.

That is why the parser **accepts any length of at least 8 bytes instead of requiring 24**. A value
that is longer, shorter or differently shaped is decoded as far as it is understood and handed back
whole, rather than rejected for disagreeing with a five-year-old write-up. The same caution applies
to PCA: the `<path>|<timestamp>` shape and the timestamp format come from public write-ups, and the
general databases' layout is reverse-engineered, which is why no field there is named.

When a real file from a current build is available, the thing to check first is whether a BAM value
is still 24 bytes and whether `unparsed_tail` is still 12 bytes long. A parser that had required 24
would have failed silently on that machine; this one records what it saw.

## Consequences

- A fifth crate, `rongroi-parsers`, with two dependencies: `thiserror` and `jiff`, both already in
  the workspace. Nothing new enters `Cargo.lock` but the crate itself.
- Nothing consumes the crate yet. The collectors that read BAM and PCA from a `Host`, turn these
  structs into `Observation`s and decide what a missing artifact means are later PRs, as are the
  rules that read them. Until then no report changes.
- PCA's absence on Windows 10 is a collector concern — `Unmeasured { not_on_this_os }` — and is
  stated in the module documentation so the next person does not go looking for the artifact on a
  Windows 10 test machine and conclude the parser is broken.
- `fuzz/` is still empty. The crate is now shaped so that a fuzz target is a byte array and a call,
  with no host and no privileges, which is what `docs/testing.md`'s Fuzz row anticipates.
- The five parsers still to come copy this shape: one `ParseError`, structs that know nothing about
  the evidence model, unnamed bytes kept rather than dropped, and a malformed record accounted for
  rather than thrown.
