# ADR 0016 — The fuzz layer

- Status: proposed
- Date: 2026-09-12

## Context

`docs/testing.md` has carried this row since M2 was planned:

| Fuzz (M2) | parsers never panic on arbitrary bytes | `fuzz/` | Linux |

There was no `fuzz/` directory and no workflow ran a fuzzer. `CONVENTIONS.md` §3 repeated the claim
that parsers are "fuzzed and tested on any platform", and ADR 0013 recorded `fuzz/` as "still empty"
among its consequences. This is the third documented promise in this repository with no code behind
it, after `tools/fixture-gen/` and `cargo xtask scrub-check`.

Two things make it worth closing rather than deleting. `rongroi-parsers` now holds two parsers whose
entire stated contract is "no panic, ever, on any input" (ADR 0013), and that contract is currently
tested only against inputs somebody thought of. And the input is not hypothetical: a BAM registry
value and a PCA text file are read from the machine under examination, which is the machine whose
owner has the motive to feed this program something malformed.

### What blocked it, and was not written down anywhere

`rust-toolchain.toml` pins `channel = "1.98.1"`. `cargo-fuzz` drives libFuzzer through
`-Z sanitizer`, and `-Z` flags exist only on nightly; its default `--build-std` needs nightly's
`rust-src` as well. Any pull request that adds `fuzz/` hits this on its first command, which is
presumably why the row has outlived three milestones.

## Decision

### Nightly, in one CI job, rather than a stable substitute

The rejected alternative was `arbitrary` plus a property-test harness on stable. It keeps one
toolchain and needs no new job, and it was rejected because of what it would test: values a generator
was told to produce, rather than input a coverage-guided fuzzer finds by watching which branches the
parser takes. The claim in `docs/testing.md` is specifically "never panic on **arbitrary** bytes".
Rewriting the claim to match the easier implementation would leave a security tool with a weaker
guarantee and a document that no longer says so — the wrong direction on both counts.

So the toolchain requirement is met rather than worked around: one CI job installs nightly for
itself, and nothing else in the repository changes toolchain.

### `fuzz/` is excluded from the root workspace

`[workspace] exclude = ["fuzz"]` in the root `Cargo.toml`, and `fuzz/Cargo.toml` declares its own
one-member workspace. This is cargo-fuzz's own convention, and here it is what keeps the promise that
the pinned toolchain is untouched: `cargo build`, `cargo clippy --all-targets`, `cargo nextest run`
and `cargo deny check` resolve only the root workspace, so none of them ever sees a nightly-only
crate, a `#![no_main]` harness, or `libfuzzer-sys` and its `cc` build dependency. The dependency is
not in the root `Cargo.lock` and is not a licence question for the shipped program, because it is not
part of the shipped program. `cargo deny check` continuing to pass is not a claim about `fuzz/`; it
is the absence of one.

The cost is that the fuzz crate has no gate of its own beyond compiling: it does not inherit the
workspace lints, and `cargo deny` does not read `fuzz/Cargo.lock`. For five files that each make one
call, that is the right trade; it would not be if the harness grew logic.

### CI runs a smoke, not a campaign

The job builds every target and runs each one for 30 seconds against its seeds, with `-timeout=10` so
that a hang fails the run rather than the job's clock. It is named `fuzz smoke (ubuntu)` and says so
in `docs/testing.md`, because a job called "fuzz" that runs for two minutes invites the reader to
believe more has been proven than has.

What 30 seconds does prove, on every pull request: the targets still compile against the parsers'
public API — the failure mode when a parser's signature changes and nobody updates the harness — and
neither the seed corpus nor a short mutation run around it produces a panic, an abort or a hang. What
it does not prove is that no such input exists. Finding a deep bug is measured in hours, and an
hours-long job on every pull request would be paid for on every unrelated change. A longer campaign
is a local run, or a scheduled job if this ever earns one.

### Seeds are the fixtures the L0 tests already read

`fixtures/parsers/<artifact>/` holds artifact bytes and nothing else — no path, no user, no registry,
which is exactly what ADR 0013's pure-parser shape bought. Those files are the L0 test inputs *and*
the seed corpus the fuzz job hands libFuzzer. `fuzz_filetime` seeds from the BAM directory, because a
BAM value's first eight bytes are the little-endian `FILETIME` it converts.

`fuzz_prefetch` seeds from `fixtures/prefetch/` rather than from a directory under `fixtures/parsers/`.
The principle is the same — the fuzzer's seeds are the L0 tests' inputs — but those files are vendored
from a third-party corpus under its own licence and `REUSE.toml` annotates them where they lie
(ADR 0015), so moving them under `fixtures/parsers/` would be a licensing change for a tidier path.

A second, parallel set of sample bytes for the fuzzer was the obvious alternative and is how these
things usually rot: the parser gets a new test fixture, the fuzz corpus does not, and after a year the
fuzzer starts from bytes that no longer resemble the artifact. One set means a fixture added for a
parser test improves the fuzz seeds in the same commit.

That property has to be enforced rather than described, because the failure is silent: libFuzzer
handed a corpus directory that is empty, or that does not exist, still exits 0. A green job and a job
that fuzzed no artifact at all look identical from outside. `crates/rongroi-parsers/tests/fixtures.rs`
is therefore an L0 test that fails when a seed directory is missing or empty, and when `ci.yml` no
longer names it.

### `fuzz_filetime` is a target and not only a unit test

Converting a `FILETIME` has already produced one real panic: `u64::MAX` tripped an assertion inside
jiff-core before `Timestamp::from_nanosecond` could return its `Result` (ADR 0013). The fix is a range
check written against jiff's own `MIN`/`MAX` constants, so it moves when a jiff upgrade moves them —
and stops covering the range if an upgrade moves them differently. The unit test pins the one value
that was known to fail; the fuzz target is what looks for the next one. cargo-fuzz builds with debug
assertions on by default, which is the build where that class of defect fires at all.

## Consequences

- A `fuzz/` workspace with five targets, one per public parser entry point: `fuzz_bam`,
  `fuzz_pca_app_launch`, `fuzz_pca_general`, `fuzz_filetime`, `fuzz_prefetch`. The first four landed
  with this layer; `fuzz_prefetch` followed in its own pull request, because the Prefetch parser was
  being written in a parallel branch while this layer was and a target pointed at it would not have
  compiled here (ADR 0015). A parser added later gets a target in the same pull request; the file is
  ten lines.
- Each target asserts nothing about the value it receives. A malformed artifact is a typed
  `ParseError` and a `FILETIME` out of range is `None` — both correct answers. The bug a target looks
  for is a panic, an abort or a hang.
- A fifth CI job, Linux only, roughly three minutes of which about two are building cargo-fuzz. It is
  not in the repository ruleset's required-checks list; adding it there is a separate decision for a
  maintainer, and until then the job reports but does not block.
- `cargo-fuzz` is pinned by version in the workflow and built with `cargo install`, because
  `taiki-e/install-action` does not carry it and would fall back to an unpinned `cargo-binstall` —
  every other action in this repository is pinned to a commit SHA.
- Cargo warns five times that the binary names are not kebab-case. `fuzz_bam` is cargo-fuzz's
  convention and the name every documented command uses; the warning is expected and is noted in
  `fuzz/Cargo.toml`.
- `fixtures/parsers/**` is marked `binary` in `.gitattributes`. The repository normalises to LF, and
  the PCA fixtures are CRLF because that is what Windows writes; normalising them would produce a file
  Windows never wrote and quietly change what the L0 tests exercise.
- `cargo xtask check-unicode` skips `corpus` and `artifacts` directories, and `typos` excludes them.
  They hold bytes libFuzzer invented, and a run that happens to produce a byte order mark must not
  fail an unrelated check on the next person's machine.
- The gate was proven to bite before it was merged, as `docs/testing.md` requires of a new gate; the
  row there says how to break it again.
