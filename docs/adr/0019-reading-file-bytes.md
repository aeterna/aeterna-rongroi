# ADR 0019 — Reading file bytes from a host

- Status: proposed
- Date: 2026-09-12

## Context

`rongroi-parsers` holds four working parsers — BAM, PCA, Prefetch and Event Log — and **nothing in the
product calls any of them**. The crate is declared in `[workspace.dependencies]` and listed by no
consuming manifest: not `rongroi-collectors`, not `rongroi-cli`, not the desktop app. ADR 0013, ADR 0015
and ADR 0018 each say the collector is a later PR, so the island is planned rather than accidental. What
none of them says is what the bridge needs.

There is one thing, and it is small. Every parser's public API is `fn(&[u8]) -> Result<T, ParseError>`
(`crates/rongroi-parsers/src/lib.rs`), and **no method on `Host` returns the bytes of a file**.
`FilesystemSource` has `list_dir`, which returns names, and `file_sha256`, which returns a digest —
and the digest is computed inside the host by `sha256_file`, so the bytes never cross the trait boundary.
Three of the four parsers (PCA, Prefetch, Event Log) need file bytes and can do nothing without them.
The fourth, BAM, needs registry enumeration and a binary registry value, which is a separate decision.

A new kind of source, or a new capability on an existing one, is an ADR (CONVENTIONS.md §8).

## Decision

### A method on `FilesystemSource`, not a new `FileContentSource`

ADR 0009 split the file system from the environment, and ADR 0011 split code integrity from the TPM,
both with the same argument: a collector that wants one should not be handed the other, and `FixtureHost`
should be able to describe either alone. Read again, that argument splits traits **by which source is
touched** — the registry, the file system, the environment, the running kernel, the TPM, the process
list — and never by which operation is performed on one source.

`read_file` touches the file system and nothing else. `file_sha256` already opens the same files and
reads every byte of them; the difference is where the bytes go, not what is read or which permission it
needs. A `FileContentSource` would be the first trait split *within* one source, would give `Host` a
seventh supertrait that all three implementors must carry anyway, and would put a collector reading a
`.pf` file into two file-system traits at once. So the method goes where `list_dir` and `file_sha256`
already are.

The cost is that this ADR amends ADR 0009's "what is deliberately not read", which said: "no content
beyond what the digest consumes". That sentence described a file-system source whose only reason to open
a file was to hash it. It is superseded here rather than left to contradict the code, and what replaces
it is narrower than it looks — see "What is still deliberately not read".

### `Ok(None)` is a file that is not there

The same distinction `list_dir` makes for a directory (ADR 0009), for the same reason: "the file is not
on this machine" is something the collector looked at and saw, and an error would claim it could not
look. It also covers a case that does not arise for a directory. A Prefetch or Event Log collector lists
a folder and then reads each entry, and Windows deletes and rewrites files in both folders while the scan
runs, so a file that was listed a moment ago and is gone when it is read is ordinary — not a failure.

This differs from `file_sha256`, which reports a missing file as `Failed`. That is left alone: its
contract is "the error is about that one file", and a collector that cannot hash a file still reports the
file, so the two never have to agree.

### The read is bounded at 64 MiB, and exceeding it is a typed outcome

Every file a collector reads lives on the machine under examination, so its size is chosen by whoever put
it there. An unbounded `read_to_end` on a hostile path lets that person choose this program's allocation
size — the same class of defect this repository has just finished patching in the vendored `evtx` crate,
where a `u32` read out of a record sized a `Vec` and a 68 KiB file reached a 7.7 GB reservation (ADR 0018,
`third_party/evtx/PROVENANCE.md`). A failed Rust allocation calls `handle_alloc_error`, which aborts: not
an `Err`, not catchable, and it takes the desktop app with it **before its window exists**, because the
scan runs before the window is created (ADR 0012). Bounding one layer lower than the parsers is the point
of this section.

Why 64 MiB:

- It is four times the 16 MiB that `rongroi_parsers::prefetch` already refuses to ask a decompressor for,
  which ADR 0015 chose as "far above anything real and far below a size that could hurt". The same
  sentence holds here with more headroom, one layer out.
- It is far above the artifacts this program is being built to read. The vendored Event Log sample is
  69 632 bytes, the largest vendored Prefetch file decompresses to 25 KiB, and the PCA files are text.
- It is far below a size whose refusal costs a player anything. A machine that cannot spare 64 MiB is not
  running FiveM.

Exceeding it is `SourceError::TooLarge { limit }` — a variant of its own, not a `Failed`, because the
file was found and was readable and the limit is this program's rather than the machine's. It carries the
limit and never the size: the reader stops one byte past the limit, so it never learns how large the file
actually was, and a number it would have to take a second look to produce is not one worth reporting.

**Nothing is truncated.** Returning the first 64 MiB of a larger `.evtx` would hand the parser a file
that ends mid-chunk, which it would faithfully report as a damaged log — evidence of damage this program
caused, in a tool whose whole output is evidence about someone else's machine. Refusing the file says
something true instead.

The limit is applied by one function, `rongroi_host::read_bounded`, which every host calls. It lives next
to the trait for the reason `sha256_file` does (ADR 0009): so that every host that reads real files
refuses exactly the same files, and so that the loop is covered by tests that need no Windows.

### A new `SourceError` variant, and the compile errors it causes

`TooLarge` makes the three places that classify a `SourceError` — `fivem_dir`, `posture` and `process` —
fail to compile until each one names it. That is the intended cost, and it is the reasoning ADR 0015
applied to the third-party `PrefetchError`: an added variant should be a compile error at every point
that maps it, rather than a wildcard arm quietly labelling whatever arrives next as something it is not.
All three map it to `read_failed`, the reason code for "the artifact was not read", and none of them can
reach it today because none of them reads a file's bytes.

The existing vocabulary is otherwise unchanged and is not duplicated: not-found is `Ok(None)`, denial is
`SourceError::AccessDenied`, an I/O failure is `SourceError::Failed`, and the classification runs through
the same `SourceError::from_io` that `list_dir` and `file_sha256` use. This matters to the PR that
follows: a collector turns `AccessDenied` into `Unmeasured { not_admin }` when `is_elevated()` is
`Some(false)` and `Unmeasured { access_denied }` otherwise, and it can only do that because denial
arrives as its own variant rather than inside a string.

### A fixture describes bytes on the file entry it already describes

`FixtureFile` gains `content:` (inline, as text) and `from:` (a path relative to the host's own
directory), and a file that writes both is rejected rather than one of them being picked.

The bytes go on the entry that already carries the file's name and hash, inside the `filesystem:` block,
rather than into a new top-level `files:` map keyed by path. A separate map would let a fixture describe
a file that `read_file` finds and `list_dir` does not — two statements about one file, with nothing to
stop them disagreeing. One entry cannot contradict itself.

`from:` exists because the artifacts the next collectors read are already in this repository as binary
corpora — `fixtures/prefetch/`, `fixtures/evtx/`, `fixtures/parsers/` — where they are also the fuzz
seed corpora and are pinned by the parsers' own tests. A fixture must reference those files, never copy
them. It is resolved when the host is loaded, so a path that does not resolve fails as a broken fixture
instead of looking like a file whose bytes cannot be read; `from_yaml_str` has no directory to resolve
against and says so rather than using whatever the working directory happens to be.

A file listed with neither is a file that is there and cannot be read, reported as `Failed` — the same
per-file failure an absent `sha256` already models. That is deliberately *not* the `Unsupported` rule
ADR 0011 set for a whole block a fixture never described: a `filesystem:` block that exists has described
this directory, and a named entry in it is a statement about one file, not silence about a capability.
The fourteen fixtures that predate this change therefore keep loading unchanged, and `read_file` on any
file they list reports that one file as unreadable.

### Alternatives weighed

| Alternative | Why not |
|---|---|
| A new `FileContentSource` trait | Splits one source by operation, which is not the axis this codebase splits on; a seventh supertrait every implementor carries anyway. See above |
| `read_file(path, max_bytes)` — the caller chooses the bound | Moves the safety decision to every call site. A collector that passes `u64::MAX` re-opens the hole and reads like ordinary code in review; the bound belongs with the code that does the allocating |
| Return a `Box<dyn Read>` and let the collector stream | The parsers take `&[u8]`, so the bytes are materialised regardless, and an unbounded `read_to_end` on the stream puts the defect back exactly where it was — with the limit now impossible to enforce in one place |
| Truncate at the limit and return what fits | A truncated artifact parses as a damaged one. The report would then describe damage this program caused as if the machine had it |
| Panic or abort above the limit | `rongroi-parsers` promises it never aborts on any input, and the scan runs before the desktop window exists. An abort there is an app that never appears |
| No limit, on the grounds that the files are small | "The files are small" is a statement about honest machines. This program reads dishonest ones by design |

## What is unverified

**The 64 MiB limit has not been measured against a real `Security.evtx`.** No Windows machine was read
in this PR. A real event log's size is a configured maximum, and a machine whose administrator raised it
above 64 MiB will produce `TooLarge` and, once the Event Log collector exists, `Unmeasured { read_failed }`
for that log. That is an honest answer rather than a wrong one, but it is a real limitation and the
number it turns on is reasoned from this repository's own corpora, not from a survey of Windows defaults.
The thing to check on a real machine is what `wevtutil gl Security` reports as `maxSize`, and whether
`%SystemRoot%\System32\winevt\Logs` in practice holds files above this limit.

**The live implementation was not run.** `LiveHost::read_file` is compiled and linted for
`x86_64-pc-windows-msvc` from macOS and is exercised by the Windows CI job, as every other live
implementation is; nothing here executed it. Specifically unexercised off Windows: that `File::open` on a
path Windows denies yields `PermissionDenied` and therefore `AccessDenied`, rather than some other kind.

**The 64 MiB boundary itself is tested on `read_bounded`, not end to end.** The unit tests drive the
limit at 0, at 4, at 64 KiB and one byte past each, which is the whole of the logic; no test materialises
a 64 MiB file to watch `FixtureHost` or `LiveHost` refuse one, because both call that same function with
that same constant. A test pins the constant so that changing it is a deliberate edit.

## Consequences

- `Host` gains no supertrait; `FilesystemSource` gains one method, and all three implementors —
  `LiveHost`, `NonWindowsHost`, `FixtureHost` — implement it. All are in-repo and `publish = false`, so
  nothing downstream breaks.
- `SourceError` gains `TooLarge { limit }`. The three collectors that classify a `SourceError` name it
  and map it to `read_failed`; no report changes, because none of them can produce it.
- No collector, no parser call, no rule and no report field changes in this PR, so no snapshot moves and
  `cargo insta test --unreferenced reject` and `cargo xtask check-baseline` stay green untouched.
- No dependency is added. `read_bounded` is `std::io::Read::take` and `read_to_end`; `cargo deny` sees
  nothing new.
- `fixtures/hosts/file-content-present` is the first fixture host that points at a file in another
  fixture directory. The corpora stay inputs: it references, and copies nothing.
- **What is still deliberately not read.** This adds the bytes of a file a collector names. It does not
  add recursion, timestamps, size, owner, ACLs, attributes, alternate data streams, or reading a file the
  collector did not name. Everything is opened for reading; nothing on the scanned machine is written,
  renamed, locked or touched (AGENTS.md hard rule 2).
- The bytes themselves never reach a report. What a collector may emit from them is the next PR's
  decision, and the PII boundary for Prefetch's loaded-file list, PCA's rejected-line text and Event Log
  payloads is argued there — the parsers already drop the worst of it (ADR 0018).
