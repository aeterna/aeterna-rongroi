# Testing

## Layers

| Layer | What it proves | Where | Runs on |
|---|---|---|---|
| L0 parsers | artifact formats decode correctly, including corrupt input — truncated, malformed, the wrong encoding, and bytes whose meaning is not established | `crates/rongroi-parsers` | macOS · Linux · Windows |
| L1 collectors | every outcome — found, not found, unmeasured — against `FixtureHost` | `crates/rongroi-collectors/src/*.rs` | macOS · Linux · Windows |
| L2 rules | each rule's `collector`, every `match` field name and every `unmeasured_when` reason exist in this build, and every `match` operator is one the field's kind can take; each rule's positive fixture is `found`, negative is `not_found` | `rules/**/tests/` via `cargo xtask check-rules` | macOS · Linux · Windows |
| L2b baseline | the whole rule set stays quiet on machines described as ordinary, **and quiet for a reason**: each accepted match needs a `rules/known-fps.csv` row with a reason, an unused row fails, and each rule must be *confronted* by some baseline observation — one carrying the fields its `match` names and one unsatisfied condition away from firing — or carry a `rules/unconfronted.csv` row with a reason and a `resolved_when` (ADR 0033). Three profiles, one of which — `baseline-elevated-win11` — has every collector `Measured`, so a rule for `pca`, `prefetch`, `bam` or `evtx` is answerable here rather than `Unmeasured` (ADR 0026) | `fixtures/hosts/baseline-*/` via `cargo xtask check-baseline` | macOS · Linux · Windows |
| L3 report | the full pipeline, as JSON snapshots; SS view never contains the fixture user name, lists no `unmeasured` result its rule expected, and carries the `not_admin` scope statement rather than a row per rule (ADR 0027) | `crates/rongroi-collectors/tests/`, `rongroi-core::view` | macOS · Linux · Windows |
| L4 UI | the GUI renders the L3 report JSON through mocked IPC; WebView hardening settings | `apps/desktop` (vitest) | macOS · Linux |
| L5 live | real Windows: no panic, non-admin gives `unmeasured(not_admin)`, scanned folders unchanged, no files left outside the run's temp folder. The CI runner is **always elevated**, so the non-admin half is only ever evidenced by a Windows test machine — last run 2026-09-13, both log-clearing rules `unmeasured / not_admin` under a limited token (ADR 0033). The same job proves **signature checking never reaches the network**: with the CAPI2 log on, the ignored `live_offline_*` tests may leave no event 53 from their process, and the `live_online_*` positive twin must leave one (ADR 0035) | Windows CI job and a Windows test machine | Windows |
| Fuzz | the parsers never panic, abort or hang on arbitrary bytes | `fuzz/fuzz_targets/`, seeded from `fixtures/parsers/`, `fixtures/prefetch/` and `fixtures/evtx/` | Linux CI — a **30-second smoke run per target**, not a campaign |

GitHub's Windows runners disable the SysMain and PCA services, so Prefetch and PCA collectors are expected to
be `unmeasured` there.

> **First run against a real Windows install: 2026-09-13.** Until then this paragraph said none of the
> artifact collectors — PCA (ADR 0020), Prefetch (ADR 0021), BAM (ADR 0023), Event Log (ADR 0024) — had
> ever met one, and that the Windows CI job could not stand in for one because it runs elevated, with
> UAC off and with SysMain and PcaSvc disabled. That is no longer true, and what replaced it is one
> machine, not a population.
>
> The CLI was cross-built and run on one Windows 11 machine (build 26220), elevated and then under a
> limited token. Six of the seven collectors produced observations: `evtx` 1421, `prefetch` 627,
> `process` 298, `bam` 83, `pca` 3, `posture` 1, and one own trace — the program recognising itself
> (ADR 0010). `fivem_dir` produced none, which the report cannot distinguish from "could not look":
> no rule reads that collector, so its run reaches the report only through `unmatched`.
>
> **Elevated against limited, same machine, same day.** The second run answers "does this need
> administrator rights", which ADR 0015 asserted for Prefetch and ADRs 0020 and 0023 left unestablished
> for PCA and BAM:
>
> | Collector | Elevated | Limited token |
> |---|---|---|
> | `pca` | 3 | **3** — readable without elevation |
> | `process` | 298 | 295 — no elevation effect visible; the difference is three processes, which is also what a minute apart looks like |
> | `evtx` | 1421 | 229 — partly readable; `Security` and `System` are not, and both log-clearing rules came out `unmeasured / not_admin` as ADR 0024 says |
> | `bam` | 83 | **1** — needs elevation |
> | `prefetch` | 627 | **1** — needs elevation, as ADR 0015 said |
>
> `docs/architecture.md`'s "Needs admin" column now carries these.
>
> **What one machine does not settle.** Which path shapes the artifacts hold in general; whether another
> Windows build or edition answers differently; and what the single remaining observation is in the
> `bam` and `prefetch` limited-token runs — it is one per collector and was not opened. The per-artifact
> path questions in ADRs 0020, 0021, 0023 and 0024 stay open.
>
> The CI job remains a second, different machine rather than a substitute: it has a real `winevt\Logs`
> folder and an elevated token, so it parses real event-log bytes on every run, and it says nothing about
> the non-elevated branch an ordinary scan takes.

## The fuzz layer

One target per public parser entry point — six of them: `fuzz_bam`, `fuzz_pca_app_launch`,
`fuzz_pca_general`, `fuzz_filetime`, `fuzz_prefetch`, `fuzz_evtx`. Each asserts nothing about the value it
gets back: a malformed artifact is a typed `ParseError`, which is a correct answer, so the bug a target looks
for is a panic, an abort or a hang.

> **The one known exception to that row was EVTX, and it is closed as of 2026-09-12.** Crafted
> `.evtx` inputs existed on which `rongroi_parsers::evtx::records` did **not return** — over 300 s
> under the sanitizer with the timeout raised, over 600 s in a release build without one — and for a
> time the row above overstated the position for that parser. The defect was in the vendored `evtx`
> crate: its per-chunk string table is a set of linked chains, and the walk of them guarded only
> against an entry pointing at itself, so a chain closed into a cycle of two or more was walked
> forever. It is fixed here, with a deterministic regression test built from the good fixture rather
> than from a saved crash (`third_party/evtx/PROVENANCE.md`, patch 3).
>
> What is now true is narrower than the row: both saved reproducing inputs parse, and nothing is known
> that hangs this parser. That is not a proof that none exists — it is what a smoke gate and one fixed
> defect can say. The reproducing inputs are still kept out of the repository, because everything in
> `fixtures/evtx/` is also a fuzz seed and must parse.

`fuzz_prefetch` is one of two whose bytes reach third-party code rather than only our own, which is half of
why ADR 0015 accepted that decompressor's immaturity. `fuzz_evtx` is the other and covers the most of it: a
binary XML decoder, a chunk reader, per-chunk string tables, and under them the unmaintained `encoding` crate
that `deny.toml` carries an ignore for. That ignore names this target as one of the things that bounds the
risk, so the target is part of what was promised in exchange for the dependency (ADR 0018).

Two things about it are deliberate and are not a gap to be closed later (ADR 0016):

- **cargo-fuzz needs nightly** — it drives libFuzzer through `-Z sanitizer`. `fuzz/` is therefore its own
  workspace, excluded from the root one, and the CI job installs nightly for itself alone. Every other
  command still runs on the 1.98.1 toolchain pinned in `rust-toolchain.toml` and never sees `fuzz/`.
- **CI runs a smoke, not a campaign.** 30 seconds per target proves the targets still build against the
  parsers' public API and that neither the seeds nor a short mutation run around them crashes. Finding a
  deep bug takes hours; run one locally when changing a parser.

Seeds are the fixtures the L0 tests already read — `fixtures/parsers/<artifact>/`, plus `fixtures/prefetch/`
for `fuzz_prefetch` and `fixtures/evtx/` for `fuzz_evtx`, which sit apart because those files are vendored
under their own licences (ADR 0015, ADR 0018) — so a fixture added for a parser test is a fuzz seed too, and
there is no second set of sample bytes to keep in step.
`crates/rongroi-parsers/tests/fixtures.rs` is what holds the two ends together: it fails if a seed directory
is renamed, emptied, or no longer named by `ci.yml`. A fuzzer handed an empty corpus still exits 0.

## Commands

```bash
cargo nextest run                       # L0, L1, L3 (or: cargo test)
cargo xtask check-rules                 # L2
cargo xtask check-baseline              # L2b
cargo insta review                      # after an intended change to a report snapshot
pnpm -C apps/desktop test               # L4
cargo check --target x86_64-pc-windows-msvc -p rongroi-host-windows   # type-check Windows code from any OS

# Fuzz — needs a nightly toolchain and `cargo install --locked cargo-fuzz` (CONTRIBUTING.md)
cargo +nightly fuzz build                                             # every target
cargo +nightly fuzz run fuzz_bam fuzz/corpus/fuzz_bam fixtures/parsers/bam -- -max_total_time=30
```

libFuzzer writes what it finds to the **first** corpus directory and reads the rest as seeds, which is why
`fixtures/parsers/` comes second: the fixtures are an input, never an output.

## Snapshots

Snapshots live next to the tests in `snapshots/`. The rules bundle hash is redacted so that adding a rule does
not rewrite every snapshot. Review every snapshot diff as carefully as code: it *is* the output users see.
CI runs `cargo insta test --unreferenced reject`, so a stale snapshot fails.

## Fixture hosts

`fixtures/hosts/<name>/host.yaml` describes a fake machine: platform, build, elevation, registry values and
keys that deny access. All of them are synthetic; see `fixtures/hosts/PROVENANCE.md`. Never copy files from
a real player's PC into this repository.

A `baseline-*` host means more than the others: it asserts that a machine like it is unremarkable, so
`check-baseline` requires the whole rule set to stay quiet on it (ADR 0017). A setting in one is never
chosen to silence a rule — and a source one of them leaves undescribed is not neutral either, because a
collector that never reads is `Unmeasured` and a rule for it is then unmeasurable in either direction
(ADR 0026).

> **The gate cannot measure the two log-clearing rules, and since ADR 0033 it says so on every run.**
> `fixtures/hosts/baseline-elevated-win11` holds exactly one `.evtx` file, a LanguagePackSetup log, and
> no `Security` or `System` channel at all — so `security-audit-log-cleared` and `event-log-file-cleared`
> agree with none of their three conditions there, are `unmeasured` on the other two baselines, and
> `check-baseline` fails only on `found`. Those two rules would pass that part of the gate whatever they
> said. A transposed letter in that `channel:` value passes every gate as well, provided the rule's own fixtures carry the same transposition — measured, not assumed. ADR 0033 adds the **confrontation** check — some baseline
> observation must carry the fields a rule names and come within one condition of firing it — so the two
> rules now fail unless `rules/unconfronted.csv` carries a row saying why and what would end it. They do,
> and the hole is **open**: a row records that this gate is not measuring a rule, which is a worse
> position than a rule that fails. Closing it needs a Security-channel sample that carries nobody's data;
> the last candidate was removed on finding a real machine SID in it (`fixtures/evtx/PROVENANCE.md`).
> **Do not close it by adding an invented Security log to a baseline** — a baseline is a claim about an
> ordinary machine, and one written to exercise a rule is not that claim (ADR 0031, ADR 0033,
> `fixtures/hosts/PROVENANCE.md`).

## Prove that a check can fail

A gate that has never failed has not been tested. When adding or changing a gate, break it on purpose once and
confirm it fails:

| Gate | Break it by |
|---|---|
| `cargo deny check` | adding `reqwest` to a crate |
| `fuzz smoke` | giving a parser a panicking path — e.g. indexing `bytes[TAIL_OFFSET]` in `bam::parse_value`, slicing `bytes[4..MAM_HEADER_LEN]` in `prefetch::reject_implausible_declared_size`, or indexing `bytes[FILE_HEADER_LEN]` in `evtx::records` instead of comparing the length, rather than reaching for it with `get` |
| `check-rules` | duplicating a rule id, deleting a negative fixture, allowing by `name:`, misspelling a `match` field (`run_cout`) or a `collector` (`postures`), declaring an `unmeasured_when` reason the collector cannot report (`service_disabled` or `not_admin` on `posture`, both of which other collectors do report), writing an operator that is not one (`secure_boot\|matches:`), an empty value list (`secure_boot: []`), or an operator the field's kind cannot take (`secure_boot\|gt: 1`) |
| `check-baseline` | pointing a rule's `match` at a value a baseline host carries — `prefetch` / `name: cmd.exe` fires on `baseline-elevated-win11` — leaving a `known-fps.csv` row in place once its rule no longer matches, or writing a rule no baseline confronts and no `unconfronted.csv` row excuses |
| `check-locales` | adding a key to a translation that English does not have |
| `check-unicode` | inserting U+200B into any file |
| `reuse lint` | deleting a file's SPDX header |
| unofficial-build banner | building without `RONGROI_OFFICIAL_BUILD` |
| `release-check` | tagging with a date other than the changelog heading, or a version other than `apps/desktop/package.json` |
| `release-verify` | building the CLI without `RONGROI_OFFICIAL_BUILD` or without `RONGROI_COMMIT`; building the desktop app without `RONGROI_OFFICIAL_BUILD` or without `RONGROI_COMMIT` (Windows target, during the rehearsal) |
