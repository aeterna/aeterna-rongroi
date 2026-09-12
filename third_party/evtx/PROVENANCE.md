# Vendored `evtx` — provenance

This directory is the `evtx` crate's own source, vendored into this repository and carrying **two
patches**. It is not a fork: the intent is to carry the patch only until an upstream release includes it,
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

Two, in two files. Both are the same kind of defect — a number read off the wire used in arithmetic
without checking what the wire could actually hold — and both were found by `fuzz_evtx`, the second
one after the first had already been fixed and merged.

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

## Known and unfixed: a parse that does not terminate

A third defect of the same family is **open**. A crafted 69 632-byte input makes
`EvtxParser`'s record iteration never come back:

| Measurement | Result |
|---|---|
| under the sanitizer, `-timeout=300` | still running at 302 s |
| release build, no sanitizer | still running past 600 s, killed |
| with this directory's two patches | hangs |
| with `name.rs` reverted to upstream | hangs |

So it is upstream's, it is independent of both patches, and neither patch caused or unmasked it. Where
it spins has not been identified — the alarm's stack lands inside the allocator, which says only what
it was doing when the clock ran out, not what it was looping on.

It is recorded here rather than fixed because a fix needs the loop found first, and because
`docs/testing.md` claims this crate's parsers never hang. That claim is currently false for EVTX and
now says so.

The input is **not** committed: it is a fuzzer artifact, and `fixtures/evtx/` is both the L0 fixture
directory and the fuzz seed corpus, so everything in it must parse. It lives outside the repository
with whoever is working on this. `fuzz smoke` may therefore go red on any run whose seed happens to
find it again — if it does, that is this defect and not a regression of the two patched ones.

## Nothing else

Nothing else in the crate is modified. A scan of every `with_capacity`, `reserve` and `vec![n]` site in
the crate found these two to be the only allocations sized by an unchecked value read from the file;
every other one is bounded by `EVTX_CHUNK_SIZE`, by a slice length already in memory, or sits in the
`wevt_templates` feature, which is off and which this parser never enters.

**Upstream:** not yet reported. The patch is written to be sent to `omerbenamram/EVTX`, and this line
should say so with a link once it has been — an unreported finding recorded as reported is how a fix
stays vendored forever. When a release carries it, delete this directory, delete both
`[patch.crates-io]` stanzas (root `Cargo.toml` and `fuzz/Cargo.toml`), and bump the registry
dependency.

## What was removed, and what was not

Nothing was added, edited or reformatted apart from the two patches above. Three kinds of file were dropped,
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

# Only src/binxml/tokens.rs and src/binxml/name.rs may differ, and only by the patches above.
diff -r -x bin -x benches /tmp/evtx-check/evtx-0.12.2/src third_party/evtx/src

# The manifest is deliberately trimmed (see the table below), so it will differ — but only by
# removals. Anything ADDED here is drift this file failed to record.
diff -u /tmp/evtx-check/evtx-0.12.2/Cargo.toml third_party/evtx/Cargo.toml | grep '^+' | grep -v '^+++'
diff -u /tmp/evtx-check/evtx-0.12.2/src/binxml/tokens.rs third_party/evtx/src/binxml/tokens.rs
```

A `diff -r` that reports anything other than those two files means this directory has drifted
from upstream and the drift was not recorded here — treat that as a defect in this file.
