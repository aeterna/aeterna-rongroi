# ADR 0027 — Showing what the rules already say

- Status: accepted
- Date: 2026-09-13

## Context

Three things every rule in this repository already carries reached no screen and changed no behaviour.

### 1. `unmeasured_when` was parsed and read by nothing

`rules.rs` parses `unmeasured_when: Vec<UnmeasuredReason>`; `docs/rules-authoring.md` described it as
"reason codes you expect on some machines"; all four shipped rules set it. A grep over `crates/`,
`apps/` and `xtask/` found no reader. It affected neither evaluation, nor the view, nor the UI.

That matters because of what SS mode did with an unmeasured result. `view::for_mode` listed a piece of
evidence when it was `Found` **or** when its strength was `posture`, so on the `prefetch-files-present`
fixture — a machine whose registry this program cannot read — an SS viewer saw three rows:

```json
{ "collector": "posture", "strength": "posture", "state": "unmeasured", "reason": "source_missing" }
```

Three lines that look like findings and say only "this PC did not report that setting". The four rules
had each written down, in `unmeasured_when`, that this is exactly what happens on an ordinary machine,
and nothing read it.

### 2. One integer mixed two different facts

`HiddenCounts.unmeasured` was a single number. On a report where PCA does not exist because the machine
runs Windows 10, and the Prefetch folder would not open, that number is `2` and means nothing: the
first is the ordinary state of millions of PCs, the second is the sort of thing a reviewer wants to ask
about.

### 3. `falsepositives` and `description` were mandatory, translated, and rendered nowhere

`rules::validate` rejects a rule whose `falsepositives` list is empty ("must list what legitimately
produces this evidence") and one whose `description` is blank. `docs/rules-authoring.md` gives
`description` the authoring rule "what it means, why it matters, and **what it does not prove**".
`rules/i18n/th.yaml` translates both. `RuleText` carries both and `apps/desktop/src/types.ts` types
both.

`crates/rongroi-cli/src/output.rs` rendered `title` and `retention`. `apps/desktop/src/views/Report.tsx`
rendered `title` and `retention`. So every rule shipped with a written, reviewed, translated list of the
innocent causes of its own evidence — "PCs that boot in legacy BIOS or CSM mode, or were never switched
to Secure Boot"; "A TPM switched off or hidden in firmware, which is a common factory default" — and no
user had ever seen one.

NIST SP 800-86 §3.4 names "alternative explanations" as a reporting factor that "should be given due
consideration in the reporting process". The UK Forensic Science Regulator's Code of Practice §99.2.4(c)
goes further for the stronger claim: a finding may not be called "consistent with" a conclusion unless
the other scenarios it is also consistent with are given. This tool asserts nothing that strong — ADR
0002 forbids a verdict outright — but the principle is the same. A finding shown without its
alternatives is a finding shown as an accusation.

## Decision

### `EvidenceState` keeps exactly three variants

Nothing below adds a fourth. `found` / `not_found` / `unmeasured` is ADR 0002's contract, it is mirrored
by hand in `apps/desktop/src/types.ts`, it is the three-way switch in the CLI and in `Report.tsx`, and
it is the two accepted outcomes of a fixture in `check-rules`. A fourth state would be read as a fourth
kind of accusation and would break all of that for nothing. Everything here is a change to what is
*shown* and *counted*, plus one validation.

### An unmeasured result records whether its rule expected it

`EvidenceState::Unmeasured` gains `expected: bool` — whether the rule named this reason in
`unmeasured_when`. `engine::evaluate_rule` sets it at the single place every unmeasured result is
built, so the answer is the same whichever of the three ways it arose: no run for the collector, a run
that could not look, or a gap in a field the rule needs.

The meaning is the rule author's: a reason they declared is one they said happens on ordinary machines,
so it carries no information; a reason they did not declare means something they did not anticipate
stopped the measurement, and that is the only unmeasured result worth a reviewer's attention.

### SS mode lists the surprise and counts the rest

`view::ss_lists` is now the whole of the filter:

| Evidence | SS | Self |
|---|---|---|
| `found` | listed | listed |
| `not_found`, `posture` strength | listed | listed |
| `not_found`, any other strength | counted | listed |
| `unmeasured`, reason in `unmeasured_when` | counted | listed |
| `unmeasured`, reason not in `unmeasured_when` | **listed** | listed |
| `unmeasured`, reason `not_admin` | scope statement | listed, and the scope statement |

The posture escape hatch of ADR 0011 now covers `not_found` and not an expected `unmeasured`. A posture
rule that looked is what an SS reviewer came for; a posture rule that could not look for the reason its
own author wrote down is a number.

Self mode is unchanged: it lists everything, and its `HiddenCounts` stays at zero.

### `HiddenCounts.unmeasured` splits in two

Into `unmeasured_expected` and `unmeasured_unexpected`. The pair accounts for every piece of evidence
an SS view does not list, so a reader can still add the numbers up.

This is **additive to the report format and `REPORT_SCHEMA_VERSION` stays at 1**, on exactly the
argument `own_traces` and `unmatched` used (ADR 0014): `expected` carries `#[serde(default)]`, so a
report written before the field existed reads back `false`, which lists the result — the behaviour that
report already had. `HiddenCounts` and `ScopeNotes` live on `ReportView`, which is a projection built
on demand and never persisted or read back; nothing in the repository deserialises a `Report` outside
tests, and `schema_version` is interpolated into release-note prose and compared by nothing.

### `not_admin` is a scope statement, said once

`ReportView` gains `scope: ScopeNotes { not_admin: usize }` — how many rules were unmeasured because
the scan did not have administrator rights. The CLI prints it above the evidence and the desktop app
renders it above the evidence list, in both modes.

"This scan did not have administrator rights" is one fact about the **scan**. It applies to every rule
at once, so N rows all saying it are N red-looking lines carrying one fact; and it is the only
unmeasured reason with a remedy, which is what makes the restart-as-administrator offer of ADR 0012
worth taking. It is also above the evidence rather than in the footer, because a reviewer who has made
up their mind by the third row never reaches a footer.

`scope.not_admin` is not a fourth hidden count and must not be added to them: in SS mode the same rules
are also counted in `hidden.unmeasured_expected` or `hidden.unmeasured_unexpected`, so that the hidden
counts keep accounting for everything the view does not list.

### `description` beside every row; `falsepositives` beside a match

Both the CLI and the desktop app now render them, in both languages, through the same
`Bundle::text(rule_id, lang)` the title and the retention note already use — so a translated rule shows
translated text and an untranslated one falls back to English, key by key, as `docs/translating.md`
describes. No new translation mechanism, and no new string in `rules/i18n/th.yaml`: the Thai was
already there.

The asymmetry is deliberate:

- **`description` is shown for `found`, `not_found` and `unmeasured` alike.** It describes the check,
  not the answer, and its authoring rule makes it the sentence that says what the check does not prove.
  A reader needs that whatever the answer was — beside `not_found` it says what was looked for, which
  is what makes a look-back window mean anything, and beside `unmeasured` it says what the missing
  measurement would have been about.
- **`falsepositives` is shown only for `found`.** It answers "what else produces this evidence", and
  where nothing was found there is no evidence to explain. Printing a list of innocent causes under a
  row that says "not found" invites the reader to think something was found and explained away; it
  would also put three or four extra lines under every quiet rule, which is how a report becomes one
  people skim. The claim it guards against — reading a match as proof — only exists where there is a
  match.

### `check-rules` rejects an `unmeasured_when` entry the collector cannot report

`Collector` gains `fn unmeasured_reasons(&self) -> &'static [UnmeasuredReason]`, mirroring
`Collector::fields` from ADR 0026, and `cargo xtask check-rules` builds a per-collector reason
vocabulary from `rongroi_collectors::all()` — the list `scan::run` iterates, so the gate enforces the
vocabulary the shipped executable actually has. `collector_unavailable` is added to every collector's
set, because the engine produces it when a build has no run for the collector at all.

Since this ADR the field decides what an SS view lists, so a declared reason the collector cannot
produce is a suppression that never fires: the author believes they have written "this one is ordinary
here" and the report lists it anyway. Nothing in the rule file, in `check-baseline` or in a fixture
shows that. Two of the eight reasons — `not_on_this_os` and `service_disabled` — have **no producer
anywhere in this build**, so no rule may declare them at all; and a reason another collector produces is
still wrong on this one, which is how `posture` (which never splits a denial by elevation) rejects
`not_admin`.

`unmeasured_when` naming the same reason twice is rejected too, as `cased` and `match` keys already
are by being sets.

Like the field lists, the reason lists are a declaration bound to the code by a test rather than
derived from it: `every_reason_a_collector_reports_is_declared` runs every collector over every fixture
host in the repository and fails on a run-level or gap-level reason no list names. Forgetting the
method on a new collector is a compile error, not a silently empty vocabulary.

**What the check found on today's four rules: nothing.** All four read `collector: posture` and declare
subsets of `[not_windows, source_missing, access_denied, read_failed]`, which is exactly what `posture`
reports. `cargo xtask check-rules` → `4 rule(s), 8 fixture(s), 2 language(s) ok`.

### Rejected alternatives

**A fourth evidence state for "expected unmeasured".** It would carry the distinction in the type
system rather than in a boolean, which is tidier. It also breaks the `types.ts` mirror, every report
snapshot, the UI switch, the locale key set and `check-rules`' two fixture outcomes, and it invites the
reading ADR 0002 exists to prevent — a fourth row colour is a fourth verdict. The distinction is about
what a rule *said*, not about what the machine *is*, so it belongs on the state and not beside it.

**Leaving `not_admin` as an ordinary per-rule reason.** It is honest and it is what the code did. It
also produces one row per rule for one fact, which is the shape §3 of the research brief identifies as
the largest false-positive generator in the design, and it buries the one thing the reader can act on.

**Deriving the reason vocabulary from what the fixtures produce** instead of from a declaration. It
costs a contributor nothing to write, and it gets the failure direction wrong in the same way ADR 0026
records for field names: a reason no fixture happens to provoke would be rejected, so the gate would
block correct rules and the fix would be to add a fixture to satisfy the checker.

## What is unverified

**The declared reason lists are sound, not complete.** `every_reason_a_collector_reports_is_declared`
proves that nothing a collector reports on any fixture host in this repository is missing from its
list. It cannot prove the reverse — that every declared reason is reachable — because a reason is only
seen on a host that provokes it. A reason declared and never produced lets one `unmeasured_when` entry
past `check-rules`; the cost of that is an expectation that never fires, which is the state every rule
was in before this change.

**`not_on_this_os` and `service_disabled` are recorded as having no producer in this build, from a grep
over `crates/`, `apps/` and `xtask/`, not from an exhaustive analysis.** The grep found them only in
the CLI's and the app's reason wordings. If a collector is later taught to produce one, the collector's
own declaration is what makes it usable in a rule, and no gate has to be edited.

> That happened in ADR 0030: `pca` produces `not_on_this_os` and `prefetch` produces
> `service_disabled`, and no gate was edited. This paragraph, and every `source_missing` above, are
> the state of the build on 2026-09-13 before that change.

**No real Windows machine was read, and no human read the new output.** Whether "Ordinary things that
also produce this" reads as a caveat or as a hedge to a Thai-speaking server admin during a
screenshare is not established by any test here; the tests establish that the text is present, in the
right language, beside the right rows. The Thai wordings for the two new labels and the scope statement
were written for this change and have not been reviewed by a native speaker. **Amended 2026-09-14:** the
project owner approved the Thai wordings the app shows on screen.

**The `expected` / `unexpected` split is only as good as the rule authors' `unmeasured_when` lines.** A
rule that declares nothing gets every unmeasured result listed in SS mode, which is the behaviour
before this change; a rule that declares too much silences results a reviewer might have wanted. Nothing
here bounds the second direction: `check-baseline` still fails only on `Found`, so a rule that declares
every reason its collector can give is invisible to CI. Extending `check-baseline` to bound SS-listed
`unmeasured` is the research brief's §6.6 and is not in this change.

That second direction is not hypothetical: **all four shipped rules already declare `read_failed`**, and
three of them `access_denied`, in lines written when nothing read the field. From this change on those
lines have teeth, so a registry read that genuinely failed is counted rather than listed in SS mode. That
is a defensible reading of `read_failed` for a posture check on a machine the tool cannot always see into,
and it is also exactly the silence described above — it was not re-derived for this change, and whether
each of those four declarations is still what its author meant is an open question.

> **Answered for `read_failed` by ADR 0032**, which takes the reading above back: it is not a fact
> about a kind of machine, so it is no longer a rule author's to declare, and the four lines are
> deleted. The `access_denied` half of this paragraph stands as written and is still open.
>
> **Answered for `access_denied` by ADR 0032's amendment of 2026-09-14**, which checked each of the
> eleven declarations then in the bundle against its collector and the measurements, and removed all eleven.

**Nothing was measured about whether the longer rows are read.** Every evidence row is now two to six
lines instead of two, which is the opposite of the "reports people skim" failure this project worries
about. The judgement that the alternatives are worth the length is taken from NIST SP 800-86 §3.4 and
the Forensic Science Regulator's Code, not from anything observed about these readers.

## Consequences

- **All 15 report snapshots changed.** Every one gained `scope` and the two-way `hidden.unmeasured`
  split. The eight views carrying unmeasured evidence gained `"expected": true` on 25 entries. Six SS
  views — `bam`, `evtx`, `fivem_dir`, `pca`, `prefetch`, `process` — went from listing three posture
  rows each to listing none, with `hidden.unmeasured_expected: 4`. That is the change this ADR is for,
  seen from the outside: on a fixture machine whose registry this program cannot read, a screenshare
  viewer used to see three rows that look like findings and now sees one number.
- The desktop L4 test's hidden-count string changed with them, and its mocked `rule_texts` now returns
  a description and a false positive, because the real bundle always does.
- `HiddenCounts` is no longer the same shape as before; anything outside this repository reading a
  `ReportView` JSON would see `unmeasured` replaced by two fields. Nothing outside this repository
  reads one: the Tauri surface and the CLI are the only consumers, and both are in this change.
- A rule author now has a reason to fill in `unmeasured_when` accurately, and a gate that tells them
  when it is wrong. Before this change the field was documentation that nothing read.
- `docs/rules-authoring.md`, `rules/AGENTS.md`, `docs/architecture.md`, `docs/testing.md` and the
  `CONVENTIONS.md` glossary were updated to describe all of it.
