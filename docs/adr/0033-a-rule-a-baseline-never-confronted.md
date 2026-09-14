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
would be quiet however they were written.

How far a transposed letter in `channel:` gets was measured rather than asserted, because the first
draft of this paragraph claimed it passed every gate and that is not true. Changing the value in the
rule alone fails `check-rules` — the rule's own positive fixture stops matching, and the gate says so.
Changing it in the rule **and** in its fixtures passes everything: `check-rules`, `check-baseline` and
all 463 tests. That is the case this ADR is about, and it is not a corner case: a rule and its fixtures
are written by the same person in the same sitting from the same understanding, so a mistake in that
understanding lands in both. A baseline is the only artifact in the repository written from a
description of a machine by somebody not looking at the rule.

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
- **The 1102 expectation was verified; the 104 one was refuted.** Both were unverified when this ADR
  was written. On 2026-09-13 the CLI was run against one real Windows 11 machine (build 26220), once
  elevated and once under a limited token, and its own report answered them:

  | Question | Answer, on that machine |
  |---|---|
  | Does a Security log hold a `Microsoft-Windows-Eventlog` record that is not 1102? | **Yes** — event id 1100, four of them. Two conditions of three, with no clearing. The 1102 rule **would** be confronted |
  | Does a System log hold any `Microsoft-Windows-Eventlog` record? | **No** — none, across 156 record groups on that channel. The 104 rule would **not** be confronted |

  So the two rows in `rules/unconfronted.csv` are no longer the same problem. One has a fixture that
  would close it. The other's way out may not exist: a second machine has to be checked before anyone
  captures anything, and if it agrees, the question becomes whether that rule can be confronted at all
  rather than which fixture to add. **One machine is one machine** — neither answer is a population.
- **The distance between the baseline and a real machine is larger than this gate can express.** That
  same scan produced 1421 `evtx` observation groups across 148 channels. The baseline holds one log.
  A rule can be confronted on the baseline and still meet nothing like reality.
- **The row's way out is harder than one sentence makes it sound.** `fixtures/evtx/PROVENANCE.md` is
  the constraint: Event Log is the highest-PII artifact vendored here, nothing may be captured from a
  player's machine, a record cannot be redacted after the fact because each is checksummed within its
  chunk, and both the rendered-record scan and the raw-string scan have to be run before anything is
  vendored — one candidate was removed after vendoring when a second reading found a machine SID in
  it. A capture therefore has to come from a Windows 11 installation made for the purpose, with a
  throwaway local account and no network sign-in. Both rows now say so; the first drafts of them said
  "captured from a real Windows 11 machine", which reads as permission this repository does not give.

## What a real Windows machine says about these rules

Recorded here because it is the first evidence in this repository about how the ADR 0031 rules behave
outside a fixture, and because two of the three results were surprises.

**On `windows-latest`, both log-clearing rules are `found`.** The `rust (windows)` live smoke prints
every evidence row since #41, and the first run that did shows `f4c99b57` and `ff967b28` — the 104 and
1102 rules — firing on a GitHub runner. That is not a defect: a runner is an imaged machine, and the
first entry in both rules' `falsepositives` is "A prebuilt or repaired PC. The factory imaging step
Windows itself provides deletes the event logs, so the maker, not the owner, cleared this log." The
rules met the population they were written for and said what they were written to say. It is also a
reminder of what `strength: tamper` costs: on a machine nobody is accusing of anything, two rows appear.

**Under a limited token, both come out `unmeasured / not_admin` with `expected: true`.** That is
`docs/testing.md`'s L5 non-admin half, which the CI job cannot exercise because a GitHub runner is
always elevated. The four posture rules are unaffected: their registry reads need no elevation.

**Six of the seven collectors produced observations on the real machine** — `evtx` 1421, `prefetch` 627,
`process` 298, `bam` 83, `pca` 3, `posture` 1, plus one own trace. That is the first time PCA, Prefetch,
BAM and the Event Log have met a real Windows install in this project; `docs/testing.md` said they never
had, and now records what changed and what stayed open.

**On the real machine, elevated, all six rules are `not_found`** — the machine's logs have not been
cleared within what they still hold, and its posture is Secure Boot on, test signing off, HVCI
configured on, TPM present. On `windows-latest` the same posture rules report Secure Boot off, test
signing **on**, HVCI `source_absent` and no TPM, which is worth knowing before anyone reads a CI run as
"what Windows looks like".

## Consequences

- `check-baseline` reports 12 confronted rules and 6 excused, where it reported 14 and 4. The gate
  measures two fewer rules than it said it did; nothing about the rules changed.
- The `plugni` change above **still passes every gate** after this amendment — now because a row says
  the gate measures nothing about that rule, which is what is true, rather than because a confrontation
  claimed otherwise.
- No other rule changes state: only `fivem_dir` declares a discriminator, and its other five rules are
  confronted, or excused, through conditions other than `location`.

### Not established

- **Whether another collector has a field that should be a discriminator.** `evtx`'s `channel` says
  which log an observation is about; its two rules are excused for other reasons today, and whether a
  near miss in `channel` alone should confront them was not examined.

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

## Amendment 2026-09-14 — a near miss about another place is not a confrontation

### The question

ADR 0036 recorded that the two `fivem_dir` rules for a validly signed plugin file — Legacy's `plugins`
folder (`d5531c55`) and Enhanced's `asi` folder (`53528a11`) — were confronted on the baselines "only by
`location`": the one baseline observation carrying both of their fields is Legacy's `FiveM.exe`
(`location: legacy_exe`, `signature: valid`), and it differs from each rule in `location` alone. By the
letter of decision 1 that is a confrontation. Decision 1 also says what a confrontation is meant to
be: *the baseline was put the rule's question and answered no*. Whether those two agree here was
decided on evidence, not on the wording.

### What was measured

On this repository at the commit that introduced ADR 0044, before this amendment:

| Change, made in the rule **and** in its fixtures, then reverted | `check-rules` | `check-baseline` |
|---|---|---|
| `location: plugins` → `location: plugni` in `plugin-file-with-valid-signature` | passes | **passes**, and counts the rule confronted |
| `signature: valid` → `signature: valdi` in the same rule and its positive fixture | passes | **fails**: no baseline confronts the rule |

`plugni` is a place the collector never emits, so that rule would be `not_found` on every machine for
ever, which a player is shown as "looked for and not there". The confrontation caught a misspelt
signature answer and was blind to a misspelt place — the condition that makes the rule about plugin
files at all.

### Two readings, and the one the evidence supports

- **Honest.** The observation carries the rule's fields and answered "no"; `secure-boot-disabled` is
  also confronted through its one unsatisfied condition, and "a confronted rule is not a correct rule"
  already says the unsatisfied condition goes unchecked.
- **An artefact of the gate.** In `secure-boot-disabled` the unsatisfied condition is the property asked
  about — Secure Boot's state — of the same thing the rule is about. Here it is *which thing*: the
  observation is about `FiveM.exe`, and the rule asks about files in a plugin folder. The baseline was
  asked "is `FiveM.exe` validly signed", which is not the rule's question, and a baseline that holds no
  plugin file cannot have answered the rule's question at all.

The measurement decides it for the second reading: the one condition that decides where the rule looks
was the one no baseline could ever check, and the gate reported the rule as measured.

### Decision

A confronting observation's one unsatisfied condition **may not be on the rule's collector's
discriminator** — the field a collector declares says which place an observation is about (ADR 0044).
`engine::confronts` takes the discriminator as a parameter, because the engine does not know collectors;
`check-baseline` passes `Collector::discriminator()` for the rule's collector. A match still confronts,
and a near miss in any other field still confronts. When a rule's only near misses were in the
discriminator, the gate's message says that by name.

The discriminator is the criterion, rather than a list of fields kept by the gate, because ADR 0044
already needs the collector to declare which field says where an observation comes from, for its gaps.
One declaration answers both, so they cannot drift apart.

### What was not done

- **A plugin file was not added to a baseline.** No real plugin file was measured from a published
  release, and a baseline is the claim that a machine like it is unremarkable
  (`fixtures/hosts/PROVENANCE.md`). The two rules carry `rules/unconfronted.csv` rows instead, whose
  `resolved_when` is the same measured fixture that ends the rows of the two rules beside them.
- **`FiveM.exe` was not copied into a plugin location** in a baseline to confront them: nothing measured
  puts it there.

#
