# ADR 0017 — The clean baseline

- Status: proposed
- Date: 2026-09-12

## Context

`cargo xtask check-rules` runs each rule against its own `tests/positive/` and `tests/negative/`
fixtures and requires `found` and `not_found` respectively. That is a per-rule claim, and it is the
only claim this repository makes about detection quality.

Nothing in it says anything about the rule set as a whole. A rule whose `match` happened to describe
half of all ordinary Windows PCs would have a positive fixture that makes it `found`, a negative
fixture that makes it `not_found`, a UUID, a `falsepositives` list and a translation — and would pass
every gate in this repository, in CI, on the first try. A tool that shows evidence rather than a
verdict (ADR 0002) depends entirely on the evidence being worth reading; a rule set that is noisy on
ordinary machines produces reports a reviewer learns to skip, which is the failure mode this project
can least afford.

`docs/research/04-oss-detection-rule-projects.md` §5 recorded the pattern SigmaHQ uses for exactly
this: run the rules over known-clean systems and fail CI on a new hit unless it is listed with a
reason. This ADR adopts the idea; the file format is ours.

## Decision

`cargo xtask check-baseline` loads the embedded rules bundle, runs every
`fixtures/hosts/baseline-*/host.yaml` through the collectors and the engine, and requires zero `Found`
evidence — except matches recorded in `rules/known-fps.csv` with a written reason.

### The gate runs the product's own pipeline

It calls `rongroi_collectors::scan::run`, which is the function `aeterna-rongroi-cli`'s `scan` and the
desktop app's `scan` command both call. It does not walk the rules and compare fields itself.

A gate that evaluated rules its own way would be certifying its own reimplementation. Every property
this gate is meant to protect lives in code it would then not execute: `allow` handling, the gap rule
that makes an unread field `Unmeasured` rather than `NotFound`, own-trace partitioning, the choice of
which rules are active. Those are exactly the places a false positive would come from.

The cost is that `xtask` now depends on `rongroi-collectors` and on `rongroi-host`'s `fixture`
feature. That is the correct direction of dependency — the checker depends on the product, never the
other way round — and it is the same reason `check-rules` already calls `engine::evaluate_rule`
instead of matching fields itself.

`check(root, bundle)` takes the bundle as a parameter, and only `run` supplies the embedded one. That
is what lets the unit tests build a bundle from a temporary tree, which is the structure PR #8
introduced for `check_rules.rs` and the reason this gate's own failure modes are testable at all.

### Baselines are documented profiles, not one "clean machine"

There is no such thing as *the* ordinary PC, and a single fixture would silently make one arbitrary
configuration the definition of normal. Two profiles ship, and each one's `host.yaml` opens with the
profile it asserts:

| Fixture | Profile |
|---|---|
| `baseline-hardened-win11` | Windows 11 as Microsoft ships it: Secure Boot on, memory integrity configured on, test signing off, TPM 2.0, no FiveM, ordinary programs running |
| `baseline-consumer-win11` | Ordinary consumer Windows 11: Secure Boot on, test signing off, TPM 2.0, **no memory-integrity policy key at all**, FiveM installed with an empty plugin folder |

Writing the profile down is the point. A baseline that is edited until the gate goes quiet has stopped
being a claim about ordinary machines and become a restatement of whatever the rules currently do; the
comment at the top of each file, and this ADR, are what make that edit visible in review rather than
invisible.

The second profile is deliberately not a hardened machine. Memory integrity is off, or was never
configured, on a great many consumer PCs, and `hvci-disabled`'s own `falsepositives` list says so. A
baseline set containing only well-configured machines would never exercise the case a real player's PC
presents.

### What the two baselines actually produce today

**Both are silent: the whole bundle produces no `Found` evidence on either, and `known-fps.csv` ships
with no rows.** This was measured before any row was written, not arranged afterwards.

The `hvci-disabled` match that `baseline-consumer-win11` was expected to produce does not happen, and
the reason is worth recording because it is a design decision of the collector rather than an
accident. `posture` reads the memory-integrity policy with `registry_switch`, which turns an absent
value into `UnmeasuredReason::SourceMissing` in the run's `gaps` rather than into `hvci: disabled` —
"the key is not there" is not the same statement as "the feature is off" (ADR 0011). The engine then
sees a rule whose `match` names a field that is in `gaps`, and produces `Unmeasured`, never
`NotFound` and never `Found`. So the very common machine that was never told either way is reported as
*not measured*, which is the honest answer, and this gate agrees with it.

That leaves `known-fps.csv` with no rows in it on the day it lands. The file is still worth having:
its rules are enforced by the checker and covered by unit tests, so the first row anyone adds is
already governed. A gate whose escape hatch is written only when it is first needed is a gate whose
escape hatch has never been reviewed.

### An unused `known-fps.csv` row is a failure

A row says: this rule matches this baseline, and that match is a known false positive. When the rule
stops matching, the row is no longer true, and a file of no-longer-true statements is how an exception
list turns into a rubber stamp — nobody can tell which rows are load-bearing without re-deriving every
one of them.

So the checker fails on a row whose rule no longer matches its baseline, on a row naming a rule id
that is not in the bundle, on a row naming a baseline that does not exist, and on a row with an empty
`reason`. A row that names something that does not exist is reported once for that, and not a second
time for being unused, since it could never have been hit.

`added` is recorded and not otherwise checked; it exists so a reviewer can see how long a row has
stood.

### What this gate does not do

It does not prove a rule is correct, and it cannot: a baseline is a description of an ordinary machine
written by the same people who write the rules. It proves that the rule set, evaluated the way the
product evaluates it, stays quiet on the machines this project is willing to describe in writing as
unremarkable. Widening that claim means adding profiles, which is a pull request to `fixtures/hosts/`.

It is also not a false-positive rate. Two fixtures are two fixtures.

## Consequences

- `xtask` gains two workspace dependencies (`rongroi-collectors`, `rongroi-host` with `fixture`). No
  new external crate, no `Cargo.lock` addition beyond workspace edges, no `deny.toml` change.
- CI runs `cargo xtask check-baseline` in the `rust (ubuntu)` job, beside `check-rules`.
- A new rule now has to be quiet on both baselines, or come with a `known-fps.csv` row and a reason.
  A contributor who cannot write that reason has found a rule problem, not a paperwork problem.
- A new baseline profile is a way to make this claim stronger, and adding one may surface a match that
  needs a row or a rule fix. That is the gate working.
- `fivem_dir` and `process` are read on every baseline scan but no rule reads them, so their
  observations land in `unmatched` and this gate ignores them. If a rule is written for either
  collector, the baselines already carry the files and processes it would see.
