# Vendored `evtx` — provenance

This directory is the `evtx` crate's own source, vendored into this repository and carrying **one
patch**. It is not a fork: the intent is to carry the patch only until an upstream release includes it,
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

## The patch

One function, `binxml::tokens::read_template_values_cursor`, in `src/binxml/tokens.rs`.

`number_of_substitutions` is a `u32` read from the file and was used directly as a `Vec::with_capacity`
argument, twice. Nothing bounded it against the bytes actually remaining. A 69 632-byte file — an
ordinary single-chunk `.evtx`, the smallest size the format comes in — reaches a `malloc` of
**7 717 636 096 bytes**, measured, not estimated:

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

The fix is two changes, and both use the idiom the same file already uses elsewhere — `read_sid_ref`
and `read_sized_slice_aligned_in` both check the bytes remaining before allocating:

1. The descriptor loop consumes exactly four bytes per entry (`u16` + `u8` + `u8`), so a count larger
   than `bytes_remaining / 4` cannot be satisfied by this input. The reservation is capped at that.
   The loop itself is untouched, so a truncated file still fails exactly where and how it did before —
   this changes what is *reserved*, never what is *accepted*.
2. The second allocation reserved from the same unchecked figure a second time. By that point the
   descriptors have been read, so the exact count is `value_descriptors.len()` and no bound is needed.

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

Nothing was added, edited or reformatted apart from the patch above. Three kinds of file were dropped,
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

# Only src/binxml/tokens.rs may differ, and only by the patch described above.
diff -r -x bin -x benches /tmp/evtx-check/evtx-0.12.2/src third_party/evtx/src
diff -u /tmp/evtx-check/evtx-0.12.2/src/binxml/tokens.rs third_party/evtx/src/binxml/tokens.rs
```

A `diff -r` that reports anything other than `src/binxml/tokens.rs` means this directory has drifted
from upstream and the drift was not recorded here — treat that as a defect in this file.
