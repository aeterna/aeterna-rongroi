# ADR 0074 — A coverage table for the rules, and a ledger of where they were measured

- Status: accepted — the owner approved it on 2026-10-18, as the first half of a detection-validation
  programme beside ADR 0075; nothing is built yet (decisions at the end)
- Date: 2026-10-18
- Related: ADR 0017 and ADR 0033 (baseline and "confronted"), ADR 0002 (evidence, never a verdict),
  ADR 0061 (`rules/ages`), ADR 0075 (the Windows build watch, which writes rows into the ledger below)

## Context

What this project knows about each rule is spread over six places, and none of them answers "how well do we
know this rule works":

| Question | Where the answer is today | Read 2026-10-18 |
|---|---|---|
| Is the rule's matching right? | `tests/positive` and `tests/negative` beside each `rule.yaml`, run by `cargo xtask check-rules` | all 77 rules have at least one of each |
| How far along is it? | `status` in `rule.yaml` | 72 `experimental`, 5 `test`, 0 `stable` |
| Is it quiet on an ordinary machine for the right reason? | `cargo xtask check-baseline` against three hand-written hosts, plus `rules/unconfronted.csv` | 31 rules are on the unconfronted list; 2 rows in `rules/known-fps.csv` |
| How far back can a `not_found` reach? | `rules/ages/*.yaml` | 6 collectors have a file (bam, evtx, fivem_dir, pca, prefetch, usn) |
| On which real Windows was the collector measured? | prose in ADRs, `docs/testing.md`, probe results in a maintainer's untracked notes | one Windows 11 PC (build 26220), one Windows 11 Arm virtual machine (26300), GitHub's Windows Server runners (26100, 20348) |
| Has a rule ever matched on a real or lab machine? | nowhere | — |

Two things follow.

1. The last two rows are not in the repository in a form a tool can read, so nobody can list, for example,
   "rules that have never fired outside a fixture" or "collectors never measured on Windows 10" without
   reading every ADR. Fixtures are fed to the engine directly, not through a collector (`xtask/src/check_rules.rs`),
   so a green `check-rules` says the rule matches what the fixture claims a collector emits, not that a
   collector on a real machine emits it.
2. Without a list of gaps, the next piece of detection work is chosen by whatever is most recent, not by
   where the evidence is thinnest.

## Decision

### 1. A ledger of measurements: `rules/measured.csv`

One row per thing seen on one machine at one time:

```
subject,machine,os_build,edition,arch,token,seen,evidence,date
```

- `subject` — a collector name (`pca`) or a rule id. A collector row says the collector ran there and what
  it produced; a rule row says what that rule's state was.
- `machine` — one of a short fixed list, never a person's machine name: `owner-pc` (the owner's own
  Windows PC), `lab-vm-arm64` (the ADR 0069 virtual machine), `gha-<runner label>` for each
  GitHub-hosted image ADR 0075 runs on, and any other added by a reviewed change to this ADR. A player's machine is never a row, for the
  reason `fixtures/hosts/PROVENANCE.md` gives.
- `os_build`, `edition` (`client` or `server`), `arch` (`x64` or `arm64`), `token` (`elevated` or
  `limited`).
- `seen` — for a collector: `observations`, `none`, or `unmeasured:<reason>`. For a rule: `found`,
  `not_found`, or `unmeasured:<reason>`.
- `evidence` — a CI run id, a path under `docs/` or `docs/adr/`, or the name of a probe result the owner
  keeps. Something a reviewer can open.
- `date` — the day it was measured.

It holds states and builds only, never a value a collector read. It is filled by hand for what the ADRs
already record (a one-off back-fill PR), by the build watch of ADR 0075, and by the release check the
owner already runs on their own PC.

### 2. A generated table: `cargo xtask coverage` and `docs/coverage.md`

An xtask command reads only files in this repository — `rules/**/rule.yaml` and their `tests/`,
`rules/unconfronted.csv`, `rules/known-fps.csv`, `rules/ages/`, `rules/measured.csv` — and writes
`docs/coverage.md`. With `--check` it fails when the file is not what it would write, the same way
`rules-reference --check` does. It reads no network and no machine.

The table has one row per rule:

| Column | From |
|---|---|
| rule, collector, role, strength, status | `rule.yaml` |
| fixtures | number of positive and negative fixtures |
| baseline | `confronted`, `unconfronted` (with the row's `resolved_when`), or `known fp` |
| retention | `documented`, `measured`, `stated` or `none` from `rules/ages` |
| seen found | builds on which a ledger row says `found`, or `never` |
| measured on | the distinct `os_build`/`edition`/`arch` of the collector's ledger rows |

and, above it, lists of gaps by kind:

- rules never seen `found` anywhere but a fixture;
- rules on the unconfronted list, oldest row first;
- collectors measured on only one build, or never on a client edition, or never on Windows 10, or never
  without elevation;
- collectors with no `rules/ages` file.

### 3. No single number

The table reports counts and lists. It does not compute a percentage or a score for the rule set. A
single number would be read as "how good is the tool", which is the verdict ADR 0002 refuses for a
machine, and it rewards adding rules that are easy to confront over the ones that matter. Counts by
column are enough to see a trend.

### 4. Not a gate

`--check` keeps the file current; it does not fail on a gap.

### 5. What `stable` requires

A rule is promoted to `stable` only when the table shows all three:

- `baseline` is `confronted`, or the rule's `rules/unconfronted.csv` row records an owner decision;
- `seen found` names at least one lab machine (`lab-vm-arm64` or a later lab machine), not only fixtures;
- `measured on` includes at least one `client` build.

`test` keeps the requirement it has today in `docs/rules-authoring.md`: a positive and a negative fixture.
No rule is `stable` today, so no rule changes status because of this; the five `test` rules are not
affected. `docs/rules-authoring.md` gains these three lines when the xtask command is built.

## What this does not do

- It does not measure anything. It makes what is already measured readable, and makes the gaps a list.
- It does not change any rule, collector, fixture or report.
- It does not record a value read from any machine, only states and builds.

## Alternatives weighed

- **Put the measured columns in `rule.yaml`.** Rejected: a measurement belongs to a machine and a day,
  and many rows per rule would make `rule.yaml` a log. `rule.yaml` stays the rule's specification.
- **A dashboard outside the repository.** Rejected: the inputs are in the repository and the table should
  be reviewable in the same pull request that changes them.
- **Read the ADRs' prose to build the table.** Rejected: prose is not a format; a back-fill by hand, once,
  is cheaper and checkable.

## What is unverified

- How many ledger rows a back-fill from the existing ADRs gives. Expected: a few dozen, mostly from
  `owner-pc` build 26220 and the runners; not counted.
- Whether `docs/coverage.md` stays a readable size at 77 rules. `docs/rules-reference.md` is about 3,300
  lines; this table should be far shorter, not measured.

## Owner decisions (2026-10-18)

1. `owner-pc` and `lab-vm-arm64` may be machine names in this public file (§1).
2. `stable` requires the table's columns; `test` keeps today's requirement (§5).
3. The ledger is back-filled from the existing ADRs in its own pull request, after the pull request that
   builds `cargo xtask coverage`, so code and data are reviewed apart. Until then the table is nearly
   empty, and says so.
