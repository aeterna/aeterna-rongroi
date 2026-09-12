# ADR 0025 — The rule vocabulary, and a baseline that can measure the artifact collectors

- Status: accepted
- Date: 2026-09-13

## Context

Two gates in this repository could not fail, for two unrelated reasons. Both are the same kind of
defect: a check that reports success while measuring nothing, which `docs/testing.md` names — "a gate
that has never failed has not been tested".

### 1. Nothing checked that a rule names a collector, or a field, that exists

A rule names a `collector` and a set of `match` field names. Before this change:

- `rules::validate` required `collector` to equal the first path segment
  (`crates/rongroi-core/src/rules.rs`) and required `match` to be non-empty. Nothing compared either
  against a collector that exists.
- `engine::matches` is field equality over the rule's own keys, so a `match` key no observation
  carries simply never matches.
- `engine::evaluate_rule` turns "no run for this collector" into
  `Unmeasured { collector_unavailable }`, and "nothing matched, no gap" into `NotFound`.

So `run_cout` for `run_count`, or a field renamed in a collector and not in the rule, produces a rule
that is `NotFound` on every machine on earth. `NotFound` is not a neutral state in this program: it is
shown to a player, with the rule's `retention` beside it, as evidence that something was looked for
over that window and was not there. A misspelling makes the tool say that, forever, about a thing it
never looked for. `check-rules` passed such a rule, and `check-baseline` did too, because that gate
only fails on `Found`.

The same is true one level up: a rule naming collector `bams` evaluates to
`Unmeasured { collector_unavailable }` on every machine and nothing warns.

### 2. `check-baseline` could not measure the four artifact collectors at all

ADR 0017's gate runs every rule against every `fixtures/hosts/baseline-*` host and fails on
unexplained `Found` evidence. Measured on the tree as it stood:

| Collector | `baseline-consumer-win11` | `baseline-hardened-win11` |
|---|---|---|
| `pca` | `Unmeasured { read_failed }` | `Unmeasured { read_failed }` |
| `prefetch` | `Unmeasured { read_failed }` | `Unmeasured { read_failed }` |
| `evtx` | `Unmeasured { read_failed }` | `Unmeasured { read_failed }` |
| `bam` | `Unmeasured { source_missing }` | `Unmeasured { source_missing }` |

Neither host sets `WinDir` or `SystemRoot`, and neither carries a BAM state key, so all four
collectors stop before they read anything. A rule for any of them is `Unmeasured` on both baselines
whatever it says — including a rule that would fire on every machine in the world. That is a false
green, and it covers four of the seven collectors in the build and every rule the next milestone will
write.

## Decision

### `Collector::fields` declares the vocabulary, and `check-rules` enforces it

`rongroi_collectors::Collector` gains a required method:

```rust
fn fields(&self) -> &'static [&'static str];
```

Five collectors already had a private `FIELDS` array, used to build `gaps`; `posture` and `process`
gain one. `cargo xtask check-rules` builds the vocabulary from `rongroi_collectors::all()` — the same
list `scan::run` iterates, so the vocabulary it enforces is the one the shipped executable has — and
rejects a rule whose `collector` is not an id in it, or whose `match` names a field the named
collector does not declare. An unknown field within two edits of a declared one is reported with that
name; anything further away is reported with the collector's whole vocabulary and no guess, because a
wrong suggestion reads as though the tool knows what was meant.

**Where it runs.** In `xtask`, not in `rules::validate`. `rongroi-core` knows nothing about
collectors and must not: collectors depend on core, and the bundle is parsed by the shipped binary at
startup, where a build that shipped without a collector should still load its rules and report them
`Unmeasured` rather than refuse to start. The check therefore lives at the same layer as the fixture
check — CI, and `cargo xtask check-rules` locally.

### How the set of emittable field names was established

The observations are `BTreeMap<String, serde_json::Value>` built at runtime, so there is no type to
read the names off. Two ways to get them were weighed.

| Approach | Cost to a contributor adding a collector | What it catches | What it misses |
|---|---|---|---|
| **Declared list on the trait** (chosen) | One `const FIELDS` and one method. It does not compile without them | Every rule naming a collector or field this build does not have, at `check-rules` time, before the rule is ever run | A declaration that is *wrong* — a name declared and never emitted, or a rename done in the list and not in `collect` |
| Harvest names from each collector's own tests, fixture hosts and snapshots | Nothing to write; the names appear as tests are added | The same misspellings, when a fixture host exists that produces the field | Every field no fixture reaches. The harvest is a description of the fixtures, not of the collector, and it shrinks silently when a fixture is deleted |

The declared list was chosen because the harvest gets the failure direction wrong. A rule for a field
no fixture happens to produce would be **rejected** by a harvested vocabulary — the gate would block
correct rules, and the fix would be to add a fixture to satisfy the checker, which is how a gate
becomes something people work around. The declaration's own failure mode is the milder one: a name
declared and never emitted lets one wrong rule through, and that rule still has to pass its own
positive fixture.

The declaration's weakness is drift, so it is bound by tests rather than by review, in
`crates/rongroi-collectors/src/lib.rs`:

- `every_emitted_field_is_declared` runs every collector over **every** fixture host in the repository
  and fails on a field no list names;
- `every_gap_key_is_a_declared_field` does the same for `gaps`, since a gap names the field it is a
  gap in;
- `fields_are_sorted_and_unique` and `collector_ids_are_unique` keep the lists readable and the ids
  resolvable.

This binds one direction only — nothing declared may be missing from the code — and that is the
direction that matters, because it is the one that would reject a correct rule. See "What is
unverified".

### A third baseline profile, `baseline-elevated-win11`

ADR 0017 says widening the claim means adding a profile, and that is what this is rather than an edit
to the two that exist. The new host describes the ordinary Windows 11 PC of somebody who plays FiveM,
**scanned after they accepted the restart-as-administrator offer** (ADR 0012): posture identical to
`baseline-hardened-win11`, FiveM installed with an empty plugin folder as on
`baseline-consumer-win11`, and — the reason it exists — `%WinDir%`, `%SystemRoot%`, PCA's three files,
a Prefetch folder, the Event Log folder and the BAM state key, all present and readable. Every one of
the seven collectors is `Measured` on it with no `gaps`.

**Why an elevated profile rather than adding the artifacts to the two existing hosts.** Both existing
baselines are `elevated: false`, and this repository does not claim any of these four sources is
readable without an elevated token: ADR 0021 and ADR 0024 state the opposite for Prefetch and for
`Security.evtx`, and ADR 0020 and ADR 0023 record PCA and BAM as unestablished, each in its own "what
is unverified" section. A non-elevated host that read all four would be a fixture asserting something
nobody here has measured — and a fixture's contents are a claim (`fixtures/hosts/PROVENANCE.md`). An
elevated scan reading them is the case this project is sure of, and it is the case an ordinary scan
reaches as soon as the player takes the offer the program itself makes.

The two existing baselines are left exactly as they are. They assert a posture profile, they are the
only description of a **non-elevated** scan, and the gate is a union: a rule that fires on any
baseline fails it, so one host that measures these four collectors is enough to make every rule for
them answerable.

**What is in it, and why each part is ordinary.** Nothing here was chosen to quiet a rule; the
artifacts deliberately include the shapes a careless rule fires on, because a baseline that left them
out would be a weaker claim rather than a safer one.

| Addition | Why it is ordinary |
|---|---|
| `WinDir`, `SystemRoot` = `C:\Windows` | Set by every Windows installation. Their absence, not their presence, is what no real machine looks like |
| PCA's three files, from `fixtures/parsers/pca-*/normal.txt` | Windows 11 22H2 and later write them. The corpora are referenced rather than rewritten because the real artifact is CP-1252 with CRLF endings, which a YAML block scalar cannot express. Their records are FiveM, Notepad, and `game.exe` under a Downloads folder — the last is the easiest false positive in this whole program to write, and asserting it is unremarkable is the point |
| `C:\Windows\Prefetch` with the vendored `CMD.EXE-D269B812.pf` | Prefetch is on by default and `cmd.exe` has run on every machine. Beside it are the two things a real folder also holds and this collector does not read: the `ReadyBoot` directory and a non-`.pf` file |
| `winevt\Logs` with the one vendored Event Log sample, under the file name Windows gives that channel | Every Windows machine has this folder and has that channel. The file is named `Microsoft-Windows-LanguagePackSetup%4Operational.evtx` so that the `log` field and the `channel` its records declare agree — a log file whose records name another channel is a file that was *put* there, and a baseline showing that shape would be asserting it is unremarkable |
| A BAM state key with one account and two values | BAM records execution on every Windows 10/11 machine. One value is a device path — the shape BAM normally writes (ADR 0023), which no SS-mode redaction can reach and which is therefore withheld — and one is drive-rooted, so both branches of the collector's path handling are on the baseline. The SID is invented and the collector emits no part of it |

## What is unverified

**The declared field lists are not proved complete, only sound.** The tests prove that nothing a
collector emits on any fixture host in this repository is missing from its list. They cannot prove the
reverse — that every declared name is reachable — because a name is only seen on a host that produces
it, and no fixture reaches every branch of every collector. A field declared and never emitted lets
one wrong rule through `check-rules`; that rule still has to pass its own positive fixture, and
`check-baseline` still has to stay quiet on the baselines.

**No real Windows machine was read for this change, and the new baseline inherits every open
question the four collector ADRs record.** Specifically: that `%WinDir%\appcompat\pca` and the BAM
state key need an elevated token is unestablished (ADR 0020, ADR 0023) and this host does not settle
it — it assumes elevation, which makes the question moot for the fixture and not for the product.
Whether a real `winevt\Logs` or a real Prefetch folder holds what this host says is equally unread.

**One event log and one Prefetch record is not what a real folder holds.** A real `winevt\Logs` holds
on the order of a hundred files and a real Prefetch folder hundreds of `.pf` records. This repository
vendors exactly one Event Log sample and one modern Prefetch sample — every other candidate carried a
real machine's names or addresses (`fixtures/evtx/PROVENANCE.md`, `fixtures/prefetch/PROVENANCE.md`) —
so the counts this baseline produces (`logs: 1`, `examined: 1`, `files: 1`) are the fixture's, not an
ordinary machine's. A rule keyed on those counts is not meaningfully exercised here. A rule keyed on
what the records *say* is.

**The Event Log summaries are one channel's.** The sample is
`Microsoft-Windows-LanguagePackSetup/Operational`, so `event_id` 4000 and 4001 are the only ids any
rule can be measured against on this baseline. The `Security` channel — which is what ADR 0018 and ADR
0024 were written for — is not represented, and a rule for a Security event id will be `NotFound`
here rather than measured against real records. Closing that needs a second vendored sample, which is
blocked on finding one that carries nobody's data.

**This gate does not prove a rule is correct**, and this ADR does not change what ADR 0017 said about
that: a baseline is a description written by the same people who write the rules. Three fixtures are
three fixtures, and they are still not a false-positive rate.

## Consequences

- `Collector` gains a required method. Every implementor is in this repository and `publish = false`,
  so nothing downstream breaks; a new collector that omits it does not compile, which is the intent.
- `fivem_dir`'s `FIELDS` array is re-sorted (`path, location, sha256` → `location, path, sha256`). It
  is only ever iterated to build `gaps`, so no behaviour changes.
- `cargo xtask check-rules` now fails on a rule naming a collector or a `match` field that does not
  exist. **The four rules that ship today all pass unchanged**: they read `posture`, and
  `secure_boot`, `test_signing`, `hvci` and `tpm` are all in its declared list.
- A contributor adding a collector writes one `const FIELDS` and one method; the cost of forgetting is
  a compile error, not a silent gap.
- `check-baseline` runs three baselines instead of two and, for the first time, measures `pca`,
  `prefetch`, `bam` and `evtx`. A rule for any of them now has to be quiet on an ordinary machine, or
  carry a `rules/known-fps.csv` row with a reason. `known-fps.csv` still ships with no rows: all four
  rules are quiet on all three baselines.
- No new dependency; `xtask` already depended on `rongroi-collectors` for `check-baseline` (ADR 0017).
- No report field, no rule format field, and no snapshot changes. `REPORT_SCHEMA_VERSION` and
  `RULES_SCHEMA_VERSION` are untouched: this adds a check over the existing grammar, not a new part
  of it.
