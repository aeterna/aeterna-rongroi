# ADR 0033 — A rule no baseline ever confronted

- Status: accepted
- Date: 2026-09-13

## Context

`cargo xtask check-baseline` requires no `Found` evidence on any `fixtures/hosts/baseline-*` host
except the matches `rules/known-fps.csv` accepts. ADR 0026 added `baseline-elevated-win11` because
the two baselines before it described none of `pca`, `prefetch`, `bam` or `evtx`, so every rule for
those four collectors came out `Unmeasured` and the gate's green said nothing about any of them.

ADR 0031 added two rules and the same hole reappeared in a form ADR 0026's fix does not reach:

> **`check-baseline` cannot measure these rules, and its green says nothing about them.** On
> `baseline-elevated-win11` both are `not_found` … The gate fails only on `found`, so it would stay
> green whatever these rules said.

The difference is that the collector *is* `Measured` this time. `baseline-elevated-win11` vendors one
`.evtx` file, a LanguagePackSetup operational log; the `evtx` collector reads it, gaps nothing, and
produces observations carrying `provider`, `channel` and `event_id`. Both log-clearing rules name
those three fields, so ADR 0026's check — does this collector emit the fields this rule reads — is
satisfied. What is not satisfied is anything about the *values*: the rules ask for the `Security` and
`System` channels and the `Microsoft-Windows-Eventlog` provider, and no observation on any baseline
carries either channel or that provider. The rules agree with **none** of their three conditions and
would be quiet however they were written. A `channel:` value with two of its letters transposed would pass
every gate in this repository.

So the state that needs a name is not "unmeasured" and not "not found". It is **a rule the baseline
never put a question to**, and until now nothing distinguished it from a rule the baseline answered.

## Decision

### 1. Confrontation

An observation **confronts** a rule when two things hold:

- it comes within **one** unsatisfied `match` condition of firing the rule; and
- it **carries every field** the rule's `match` names, excepting fields the rule asks to be absent
  (`<field>|exists: false`), which an observation satisfies by carrying nothing.

`rongroi_core::engine::confronts` is that predicate, beside `matches`, both built on one private
`unmet_conditions`. It lives in the engine and not in the gate because a second implementation of
"does this condition hold" in `xtask` would drift from the one the product uses — the failure
ADR 0017 exists to prevent. `allow` is not consulted: an observation a rule matched and then allowed
is still one the rule was compared against.

**The second half is what makes the predicate worth having.** A rule with one condition cannot fail
more than one condition, so counting alone would call every observation of its collector a
confrontation — including one carrying none of the rule's fields. The check would then certify most
confidently exactly where it knows least. With the field requirement, `secure-boot-disabled` is
confronted by a baseline reporting `secure_boot: enabled` and is **not** confronted by one where that
key could not be read.

### 2. `rules/unconfronted.csv`

`check-baseline` reports every rule no baseline confronts, unless a row names it with a `reason` and a
`resolved_when`. A row for a rule that *is* confronted is reported too, exactly as an unused
`known-fps.csv` row is, which is what makes the file self-clearing: the fixture that closes a hole
also deletes the row that recorded it, or CI fails.

`resolved_when` has no counterpart in `known-fps.csv` and is the reason the file is a separate one. A
`known-fps.csv` row records a decision that is finished — this match is a genuine false positive. A
row here records a hole that is not finished, and the workspace standard's §9.5 rule for a branch that
outlives its merge applies unchanged: a written reason **and** a written condition that ends it.

Two rows exist today, for the ADR 0031 rules. Both say the same thing: no baseline carries the channel
the rule reads, and inventing one is what `fixtures/hosts/PROVENANCE.md` forbids.

### What was rejected

**Requiring every rule to be confronted, with no escape file.** That forces the choice ADR 0031
refused: either delete two rules that are correct as far as anyone can tell, or fabricate a Security
log so the gate has something to measure. A gate that makes fabricating a fixture the cheapest way to
go green is worse than the hole.

**Requiring a rule to be `Found` somewhere, on a non-baseline fixture.** `check-rules` already does
this, and it is a different claim. A rule's positive fixture is written by its author from the same
understanding that produced the rule, so a rule that misspells a channel gets a fixture that misspells
it identically and both agree. A baseline is written from a description of a machine, by somebody not
looking at the rule.

**Counting unsatisfied conditions with no field requirement**, or requiring **zero or two** instead of
one. Zero is `matches` and is the thing the gate forbids. Two admits an observation agreeing with one
of three conditions, which for the log-clearing rules would be satisfied by any record on any channel
whose provider happened to match — a weaker claim that would be harder to explain than to compute.

## What this does not fix

- **It does not close the ADR 0031 hole; it makes it audible.** The two rules are still unmeasured by
  this gate. What changed is that CI now says so on every run instead of an ADR saying so once.
- **A confronted rule is not a correct rule.** One unsatisfied condition means the baseline disagreed
  with the rule somewhere, not that the rule is right about what it disagrees on.
- **Nothing checks that a `resolved_when` is achievable**, or that anybody is working on it. A row can
  sit for a year with a sentence that reads well.
- **The threshold of one is a judgement, not a measurement.** It was chosen because it is the smallest
  value that admits the ordinary case — a posture rule against a machine with the opposite setting —
  and nothing was measured about how many rules of three or more conditions would be unreachable at
  that threshold on a fuller baseline set. There are two such rules today, and both are excused.
- **The expectation that a real `Security.evtx` confronts the 1102 rule is unverified.** The row says
  so and says it is unverified: `Microsoft-Windows-Eventlog` is expected to write 1100 on the Security
  channel when the Event Log service stops, which would confront the rule at two conditions of three
  without any clearing having happened. For the System channel, not even that much has been
  established.

## Consequences

- `cargo xtask check-baseline` gains two failure modes and a longer success line naming how many rules
  were confronted and how many are excused.
- `rongroi_core::engine::confronts` is public API of the core crate; `matches` is now its `Some(0)`
  case, so the two cannot disagree about what a condition means.
- `rules/unconfronted.csv` is added with two rows. `rules/known-fps.csv` still has none.
- No rule changes, no collector changes, no report changes. `RULES_SCHEMA_VERSION` and
  `REPORT_SCHEMA_VERSION` are untouched.
- ADR 0031's "it is **not** closed" stands. `docs/testing.md`'s blockquote beside the gate is rewritten:
  the hole is the same, and it is now reported by the gate rather than only by that paragraph.
