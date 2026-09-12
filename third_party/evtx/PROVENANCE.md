# Vendored `evtx` — provenance

This directory is the `evtx` crate's own source, vendored into this repository and carrying **three
patches**. It is not a fork: the intent is to carry them only until an upstream release includes them,
then delete this directory and go back to the registry crate.

Why it is here at all, and what the alternatives were, is `docs/adr/0018-evtx-parsing.md`.

| Field | Value |
|---|---|
| Crate | [`evtx`](https://crates.io/crates/evtx) 0.12.2 |
| Upstream | [github.com/omerbenamram/EVTX](https://github.com/omerbenamram/EVTX) |
| Licence | `MIT OR Apache-2.0` (upstream `LICENSE-MIT`, `LICENSE-APACHE`, both kept here) |
| Copyright | `2019 Omer Ben-Amram`, from upstream `LICENSE-MIT` |
| Source | the published crates.io tarball, **not** a git checkout |
| Tarball SHA-256 | `87a186db904e8dbf437db134e759e52482bdb39998a32c560f12fda986ed1ea2` |
| Vendored | 2026-09-12 |

The files cannot each carry an SPDX header without diverging from upstream on every one of them, so
`REUSE.toml` annotates `third_party/evtx/**` with upstream's copyright and licence instead. They keep
**upstream's** licence, not this project's: the code is Omer Ben-Amram's, and relicensing it by
annotation would be a false claim.

## The patches

Three, in three files, all found by `fuzz_evtx` and each one after the last had been fixed and merged.
The first two are the same kind of defect — a number read off the wire used in arithmetic without
checking what the wire could actually hold. The third is not: it is a walk over a linked structure
built from the file, with no record of where it had already been.

### 1. An unbounded reservation — `src/binxml/tokens.rs`

`binxml::tokens::read_template_values_cursor`.

`number_of_substitutions` is a `u32` read from the file and was used directly as a `Vec::with_capacity`
argument, twice. Nothing bounded it against the bytes actually remaining. A **crafted** 69 632-byte
file — one chunk behind one header, the smallest an `.evtx` comes in — reaches a `malloc` of
**7 717 636 096 bytes**, measured, not estimated.

It is crafted, and that word is load-bearing: the input came out of `fuzz_evtx`, mutated from a
well-formed sample. An unmodified Event Log does not do this, and saying "an ordinary file" would send
anyone trying to reproduce it to a file that parses cleanly.

```
==20889== ERROR: libFuzzer: out-of-memory (malloc(7717636096))
    #8  alloc::raw_vec::RawVecInner::with_capacity_in            (evtx)
    #9  evtx::binxml::tokens::read_template_values_cursor        (evtx)
    #10 evtx::binxml::ir::read_single_instance_stream            (evtx)
    #11 <evtx::evtx_chunk::IterChunkRecords as Iterator>::next   (evtx)
    #12 rongroi_parsers::evtx::records
```

On macOS this survives, because the reservation is lazy and the pages are never touched — measured, on
the run quoted above.

The Windows behaviour is **reasoned, not observed**: Windows charges commit up front rather than
overcommitting, and a Rust allocation that fails calls `handle_alloc_error`, which aborts — not an
`Err`, not catchable with `catch_unwind`. A machine without that much commit available loses the
process; one with a large page file may not. This has not been run on Windows. Either way the
allocation's size is chosen by the file, and `crates/rongroi-parsers/src/lib.rs` promises a parser never
panics and never aborts on any input.

The fix is two changes, and both use an idiom the crate already uses — in `src/utils/byte_cursor.rs`,
`read_sid_ref` and `read_sized_slice_aligned_in` each check the bytes remaining before allocating.
(They are in the cursor's own module, not in `tokens.rs` alongside the defect.)

1. The descriptor loop consumes exactly four bytes per entry (`u16` + `u8` + `u8`), so a count larger
   than `bytes_remaining / 4` cannot be satisfied by this input. The reservation is capped at that.
   The loop itself is untouched, so a truncated file still fails exactly where and how it did before —
   this changes what is *reserved*, never what is *accepted*.

   The bound is *sound* on any buffer: it never exceeds what the input could hold. How *tight* it is
   depends on the buffer being one 64 KiB chunk, which `EvtxParser` guarantees but the crate's public
   API does not — `EvtxChunkData::new` accepts a `Vec` of any length. State the bound as "the bytes
   remaining", never as a fixed 16 384.
2. The second allocation reserved from the same unchecked figure a second time. By that point the
   descriptors have been read, so the exact count is `value_descriptors.len()` and no bound is needed.

### 2. A `u16` multiplication that overflows — `src/binxml/name.rs`

`BinXmlNameRef::from_cursor`, line 78:

```rust
let len = cursor.u16_named("string_table_name_len")?;
let nul_terminator_len = 4;
let data_size = BinXmlNameLink::data_size() + u32::from(len * 2) + nul_terminator_len;
//                                                     ^^^^^^^^^ u16 arithmetic, widened afterwards
```

`len` is a `u16` from the file and `len * 2` is evaluated **in `u16`**, so any length above 32767
overflows. Where overflow checks are on — a test build, a fuzz build — it panics:

```
thread '<unnamed>' panicked at src/binxml/name.rs:78:69:
attempt to multiply with overflow
```

In an ordinary release build it does something worse: it **wraps silently**. `data_size` comes out
short, the cursor is moved to the wrong place, and the rest of the stream is misread with nothing
reporting it. The fix widens before multiplying, which makes the arithmetic exact and turns an
implausible length into an out-of-range seek — an error the caller already handles.

This one was found on `dev` after the first patch had merged, by the same fuzz target that had gone
green on the pull request an hour earlier. The fuzzer takes a random seed; one green run says nothing
about the next. The regression test for it is therefore deterministic and lives in
`crates/rongroi-parsers/src/evtx.rs`, built from the good fixture rather than from a saved crash.

### 3. A string-table walk with no cycle guard — `src/string_cache.rs`

`StringCache::populate`.

Each chunk carries a string table whose entries form linked chains: an entry begins with the chunk
offset of the next entry in its chain, and `populate` walks each chain to its end. The only guard was
`offset == string_position`, which catches an entry that points at **itself**. **Nothing caught a cycle
of two or more**, and a chain closed into one was walked forever. The same cache keys are overwritten
each time round, so memory does not grow and no allocator alarm fires — which is why the stack samples
taken while it spun landed in the allocator and said only what it was doing when the clock ran out.

This is the defect this file recorded as open, and as located nowhere, until 2026-09-12. What it did,
kept as the record of it:

| Measurement | Result |
|---|---|
| under the sanitizer, `-timeout=300` | still running at 302 s |
| release build, no sanitizer | still running past 600 s, killed |
| with this directory's other two patches | hangs |
| with `name.rs` reverted to upstream | hangs |

So it is upstream's, it is independent of the other two, and neither of them caused or unmasked it.

It was found by sampling a debug build while it spun — 2522 samples, the whole main thread under
`EvtxChunk::new_with_arena` → `StringCache::populate` — and confirmed with a temporary print of every
position visited, which showed a two-node cycle, 1679 ⇄ 256, repeating without end.

The fix stops the walk when it reaches a position that is already cached. The cache is keyed by the
position being visited, so it is its own visited-set, and `insert` already reports whether the key was
there:

```rust
if cache.insert(string_position, name).is_some() {
    break;
}
```

**Breaking loses no string, which is what makes this a fix rather than a cut-off.** If
`string_position` is already in the cache then some earlier walk — this chain, or one from another
bucket — reached it and went on from this same link, so everything the rest of the chain reaches was
cached then; the cache only grows, so it is cached now. Refusing the chunk was the alternative and was
not taken: a cycle costs the strings past it nothing, the records that reference them still resolve,
and the crate's contract is that a damaged chunk costs its own records and nothing else. Upstream's
`offset == string_position` check is the one-element case of the new one; it is left where it is, so
the divergence from the published file is one added statement.

The two reproducing inputs are still **not** committed — they are fuzzer artifacts, and
`fixtures/evtx/` is both the L0 fixture directory and the fuzz seed corpus, so everything in it must
parse (ADR 0021). The regression test is built from the good fixture instead, the way the name-length
one is: `a_string_table_chain_that_closes_into_a_cycle_still_terminates` in
`crates/rongroi-parsers/src/evtx.rs` writes one entry's next-entry offset back at the entry that links
to it, and asserts the file then parses to exactly the records it parses to without the cycle. A
regression shows up there as a hung test rather than a failing one, and the test says so.

**What this does not establish.** `docs/testing.md`'s row said the parsers never hang, this file said
that was false for EVTX, and both now record the defect as fixed — but "the one known way to hang this
parser is closed" is not "this parser cannot hang". Both saved reproducers now parse
(`cargo +nightly fuzz run fuzz_evtx <input> -- -timeout=10`, exit 0 on each, where both timed out
before), the third artifact CI produced on 2026-09-12 was never retrieved and so was never re-run, and
`fuzz_evtx` remains the only thing looking for a fourth defect.

## Nothing else

Nothing else in the crate is modified. A scan of every `with_capacity`, `reserve` and `vec![n]` site in
the crate found the first two patches' sites to be the only allocations sized by an unchecked value
read from the file; every other one is bounded by `EVTX_CHUNK_SIZE`, by a slice length already in
memory, or sits in the `wevt_templates` feature, which is off and which this parser never enters.

**Upstream: reported 2026-09-12 as [omerbenamram/evtx#294](https://github.com/omerbenamram/evtx/pull/294).**
Patches 1 and 2, against `master`, and **not patch 3** — that pull request was written while the third
defect was still unlocated, and it mentions it only as something found and not fixed, with an offer to
send the input. #294 is open and unreviewed as of 2026-09-12, so what it says about this defect is now
out of date.

What that pull request does **not** do is claim novelty. The first defect was reported in April 2026 by
`jupyterj0nes` as [#293](https://github.com/omerbenamram/evtx/issues/293), and as
[#291](https://github.com/omerbenamram/evtx/issues/291) /
[#292](https://github.com/omerbenamram/evtx/issues/292); those were closed with *"please reopen if it
reproduces on latest. i think this is no longer the case."* It does reproduce on latest, which is what
#294 supplies — a confirmation with patches, credited to the original reporter. Anyone here tempted to
file a fourth report should read those three first.

It also discloses that the patches and the pull request text were written by an AI assistant and opened
on the account owner's instruction. That is stated because the maintainer has objected to unattributed
AI-generated reports, and because it is true.

**Recommendation, for the account owner to act on or not — nothing has been opened.** Send patch 3
upstream, and send it into #294 rather than as a second pull request or a fourth issue. The reasons, in
the order they matter:

- #294 already tells the maintainer this defect exists and offers the input. Adding the fix finishes a
  statement that has already been made, in the thread where it was made, instead of opening a second
  one against a maintainer who has objected to the volume of AI-generated reports. If he would rather
  review it separately, splitting it then costs nothing.
- It needs no attachment and no fuzzer artifact. It reproduces on **upstream's own corpus**: take the
  `samples/Microsoft-Windows-LanguagePackSetup%4Operational.evtx` sample, write the `u32` at offset 5148
  (chunk offset 1052, the `Task` entry's next-entry field) as `1523`, and the parse does not return.
  That was observed here through `EvtxParser::records`; that `evtx_dump` hangs on the same file is
  reasoned from its calling the same path and was not run, because the vendored copy drops the binary
  targets. A four-byte edit anyone can repeat is a better report than a binary blob.
- Of the three, this is the one whose absence hurts every consumer rather than only a memory-bounded
  one: a hang has no upper bound and no error, and `evtx` is used by tooling that parses logs from
  machines it does not trust.

What the recommendation does not rest on is urgency. This repository is not blocked on it — the
vendored copy carries the fix today.

When a release carries the fix, delete this directory, delete both `[patch.crates-io]` stanzas (root
`Cargo.toml` and `fuzz/Cargo.toml`), and bump the registry dependency.

## What was removed, and what was not

Nothing was added, edited or reformatted apart from the three patches above. Three kinds of file were dropped,
all of them targets the library does not need:

| Removed | Why it is safe |
|---|---|
| `[[bin]]` targets and `src/bin/` | separate cargo targets, never `mod`-referenced by `src/lib.rs`; they are the `evtx_dump` CLI and benchmark harnesses |
| `[[bench]]` targets and `src/benches/` | same, and they need `criterion`, a dev-dependency |
| `[[test]]` targets and `tests/` | same, and they need `assert_cmd`, `predicates`, `rexpect` and a sample corpus this repository deliberately does not vendor |
| `[dev-dependencies]`, `[build-dependencies]` | only those targets needed them. Upstream already sets `build = false`, so there is no build script and `skeptic` went with them |
| `[profile.release]` | cargo ignores it outside a workspace root |

Everything else in the manifest is upstream's, unchanged — **including every optional dependency and
every feature**, so that no `#[cfg(feature = "…")]` in the vendored source becomes an unexpected cfg.
`src/wevt_templates/` is kept for the same reason even though its feature is off: dropping it would be
a second divergence to re-verify at every re-sync, for 116 KiB.

One consequence worth naming: `src/lib.rs` keeps a `#[cfg(test)]` helper that calls `env_logger`, which
is no longer a declared dev-dependency. `cargo test` inside this directory would therefore fail. It is
excluded from the root workspace (`[workspace] exclude` in `../../Cargo.toml`), so no workspace command
reaches it; upstream's own test suite is the place those tests are run.

## Verifying this is upstream's code

The vendored source is byte-identical to the published crate apart from the patched file. To check:

```sh
# The tarball cargo itself downloaded, verified against the SHA-256 above.
shasum -a 256 ~/.cargo/registry/cache/*/evtx-0.12.2.crate

mkdir -p /tmp/evtx-check && tar xzf ~/.cargo/registry/cache/*/evtx-0.12.2.crate -C /tmp/evtx-check

# Only src/binxml/tokens.rs, src/binxml/name.rs and src/string_cache.rs may differ, and only by the
# patches above.
diff -r -x bin -x benches /tmp/evtx-check/evtx-0.12.2/src third_party/evtx/src

# The manifest is deliberately trimmed (see the table below), so it will differ — but only by
# removals. Anything ADDED here is drift this file failed to record.
diff -u /tmp/evtx-check/evtx-0.12.2/Cargo.toml third_party/evtx/Cargo.toml | grep '^+' | grep -v '^+++'
diff -u /tmp/evtx-check/evtx-0.12.2/src/binxml/tokens.rs third_party/evtx/src/binxml/tokens.rs
```

A `diff -r` that reports anything other than those three files means this directory has drifted
from upstream and the drift was not recorded here — treat that as a defect in this file.
