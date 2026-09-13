# ADR 0029 — Four operators for `match`, and what each of them does with a gap

- Status: proposed
- Date: 2026-09-13

## Context

A rule's `match` was a map of observation field → value, compared for equality, conjunction only,
with `cased` opting one field into byte comparison (ADR 0025). Every rule the next milestone wants
needs more than that, and each of the four gaps below names a rule that cannot be written today:

- **"A core Windows event log was cleared."** Event 104 on any of `Security`, `System`,
  `Windows PowerShell`, `Microsoft-Windows-PowerShell/Operational`,
  `Microsoft-Windows-Sysmon/Operational`, `PowerShellCore/Operational`. One idea. Without a value
  list it is six rule folders, six ids and six `falsepositives` lists to keep in step, and six lines
  in a report for one event — which collides with "One name per idea" in `CONVENTIONS.md` and makes
  the report read as six pieces of evidence.
- **"The parser rejected at least one entry."** `rejected|gt: 0`. Today `pca`, `prefetch`, `bam` and
  `evtx` each emit `intact: (rejected == 0)` *so that equality can be used*, and say so in their own
  comments: "a rule matches by exact equality and cannot say 'more than none'". That is the collector
  papering over the matcher, and every future "how many" question needs the same paper. So does
  "this program has more than one recorded run" (`run_count|gte: 2`), and so does every question
  about how far back a log reaches, which has no equality formulation at all.
- **"A program ran from a per-user temporary directory."** The path holds an account name and a
  random intermediate directory; there is no enumeration to fall back on and equality can never match
  it.
- **"The path was withheld" vs "there is no path" vs "we could not read the path."** The collectors
  signal the first with separate presence-only fields — `path_withheld`, `loaded_files_withheld`,
  `volumes_withheld`, `sid_withheld` — which is again the collector working around the matcher.

Adding operators is where a rule engine usually starts lying about what it did not look at. YARA is
the only surveyed system with the right instinct, and it writes the propagation of `undefined` down
per operator. This ADR does the same, because the behaviour that falls out of an implementation is
"a gap is no match", and that is the `unmeasured → not_found` collapse ADR 0002 exists to prevent.

## Decision

### Four capabilities, and nothing else

| Written | Means |
|---|---|
| `event_id: [1102, 104]` | equality against **any** value in the list |
| `run_count\|gte: 2`, and `gt`, `lt`, `lte` | the value sorts after / before the one named |
| `path\|startswith:`, `path\|endswith:`, `path\|contains:` | text begins with / ends with / holds text |
| `path\|exists: true` or `false` | the field is there, or is not |

The names are Sigma's, deliberately: a Sigma-literate reviewer reads our rules on sight and, if this
project ever writes an importer for the Event Log collector, the mapping is mechanical. The **format**
is still ours, for the four reasons the research settled — the public corpus assumes a SIEM, a
different observer and Sysmon; a partial Sigma implementation is a format that lies; Sigma cannot
express "could not look"; and ADR 0004 forbids loading rules from a file, so there is no rule-loading
audience to be compatible with.

**Left out on purpose, and still out:** regular expressions, `base64`/`base64offset`/`utf16`/`wide`/
`windash`, `cidr`, placeholders and `expand`, wildcards inside a value, Sigma's condition grammar,
correlation and aggregation, `fieldref`, and `level`. A general `not` is out too: `allow` is the only
exclusion this repository has, and it is deliberately constrained to `sha256` or `signer` so that
weakening a rule cannot be done quietly. Nothing in the four rules above needed any of them.

### Syntax: `field|operator: value`, a key suffix

```yaml
match:
  event_id: 104                         # equality, exactly as before
  channel: [Security, System]           # or
  run_count|gte: 2
  path|startswith: 'C:\Users\'
  path|exists: true
cased: [channel]                        # still a list of FIELD names
```

**ADR 0025 rejected a key suffix, for `cased`, and the objection has to be answered rather than
ignored.** It was: the `match` keys are used as the lookup into `observation.fields` *and* as the
keys of the `gaps` lookup in `evaluate_rule`, so a key carrying a suffix would no longer equal a
field name, a field the collector could not read would fall out of `gaps`, and the rule would report
`not_found`. That is exactly right, and it is what this change does about it:

`rules::parse_match_key` splits a key into a field and an operator, once, and `Rule::match_fields`
yields **field names**. The engine looks `gaps` up on that and never on the key. A test —
`a_suffixed_key_is_still_found_in_gaps` — holds it for an ordinal, a text and an `exists` condition.

**Why a suffix here when a sibling list was right for `cased`.** `cased` is a property of a *field*:
one entry covers every comparison a rule makes against it, and a field can only be cased or not. An
operator is a property of a *comparison*, and one field can carry two of them —
`entries|gte: 2` together with `entries|lt: 10`. A map keyed on the field name could hold only one.
`one_field_can_carry_two_conditions` is the test.

### `gaps`, per operator

A run's `gaps` says the collector could not read that field. **Every operator answers `Unmeasured`.**

| Operator | Field is in `gaps` | Why |
|---|---|---|
| equality (`field: value`) | `Unmeasured` | no observation carries the field, so nothing matches, and the existing check after matching catches it. Unchanged by this ADR |
| a value list | `Unmeasured` | a list is the same comparison run several times; no element can match a field that is not there |
| `gt` `gte` `lt` `lte` | `Unmeasured` | the comparison needs a value to order; there is none |
| `startswith` `endswith` `contains` | `Unmeasured` | the comparison needs text; there is none |
| `exists: true` | `Unmeasured` | the field is not in the observation, so the condition is false, so nothing matches — and the gap check after matching turns that into `Unmeasured` |
| **`exists: false`** | **`Unmeasured`, and it is checked *before* anything is matched** | this is the one that does not fall out. A field the collector could not read is **not in the observation**, and "not in the observation" is exactly what `exists: false` is satisfied by. Left to the ordinary order, the rule would be `Found`, and the report would say *"we looked and there is no path"* about a path nobody could read — the ADR 0002 collapse wearing a `found` rather than a `not_found` |

So `evaluate_rule` consults `gaps` for the fields of every `exists: false` condition first, and only
then matches. Every other operator needs the field to be **present**, so for those the gap can be,
and still is, consulted after matching — which preserves the existing behaviour where one observation
carries a field that another run-level gap says was not read everywhere.

A gap in a field the rule does not name changes nothing, `exists: false` included
(`exists_false_is_unaffected_by_a_gap_in_another_field`).

### Timestamps are parsed, not compared as text

An ordinal comparison of two strings parses both with `jiff::Timestamp` and compares the instants.

This was measured rather than assumed. The collectors write every timestamp with
`jiff::Timestamp::to_string` — `bam::last_run`, `pca::last_run`, `prefetch::last_run`,
`evtx::first_seen`, `last_seen`, `oldest_record_time`, `newest_record_time` — and that writes a
fraction of a second only when there is one, trimming trailing zeros. Running it on three values:

| `FILETIME` | printed |
|---|---|
| `132_223_104_000_000_000` | `2020-01-01T00:00:00Z` |
| `132_223_104_005_000_000` | `2020-01-01T00:00:00.5Z` |
| `132_223_104_000_000_001` | `2020-01-01T00:00:00.0000001Z` |

The shapes are not the same width, and `.` (0x2E) sorts before `Z` (0x5A), so as text
`"2020-01-01T00:00:00.5Z" < "2020-01-01T00:00:00Z"` — the **later** instant reads as the earlier one.
A lexical compare on RFC 3339 is correct only for one fixed shape, and these are two.
`a_fraction_of_a_second_is_later_and_not_earlier` asserts both halves: that the text comparison is
wrong, and that the engine gets it right anyway.

Parsing costs `jiff` as a dependency of `rongroi-core`. It is already in the workspace lockfile
through `rongroi-parsers`, which does the `FILETIME` arithmetic, and nothing in core reads a clock.
A value written with an offset (`2026-09-13T07:00:00+07:00`) is accepted and compared as the instant
it names.

A comparison between two kinds — a number against a string — is **not a match** and never a
coercion, which is the answer ADR 0025 gave for equality. `check-rules` refuses the rule that could
produce one, so this is the behaviour of a rule that got past review, not a rule that can ship.

### Text operators are text operators, and they are not path-aware

`startswith` is a byte prefix, `endswith` a byte suffix, `contains` a byte substring. None of them
knows what a directory separator is.

The research argued for Falco's `pmatch` — prefix matching where a wildcard does not cross a
directory separator — on the ground that a substring on a path is where a rule author writes
something far broader than the rule's title claims. That argument is right, and this change does not
implement it, for a reason that is structural rather than a matter of effort: **the engine cannot
tell which fields are paths.** The field kinds live in `rongroi-collectors`; `rongroi-core` depends
on nothing and is depended on by the collectors, and ADR 0026 put the vocabulary check in `xtask`
for exactly this reason — a shipped binary must load its bundle without a collector list. A
path-aware `startswith` would need that table inside the engine. Applying it to every string field
instead is worse than not having it: `name|startswith: FiveM` would stop matching `FiveM.exe`,
because `FiveM` is not followed by a separator.

**So here is what a rule author can now write by mistake**, stated once, plainly, and repeated in
`rules/AGENTS.md`:

- `path|startswith: 'C:\Users\Public'` also matches `C:\Users\PublicRecords\x.exe` — a different
  directory, whose name merely begins the same way. `a_text_prefix_does_not_stop_at_a_directory_separator`
  pins it.
- `path|contains: 'Temp'` matches `C:\Program Files\TempleOS\game.exe`. A rule titled "a program ran
  from a temporary folder" would fire on someone who installed a program whose folder begins "Temp".
- `name|endswith: 'exe'` matches `notanexe`. The extension idiom is `'.exe'`, with the dot.

The mitigation is an authoring rule, not an engine feature: **put the separators in the value.**
`'C:\Users\'`, `'\AppData\Local\Temp\'`, `'.exe'`. Case folding makes that safe to write in whatever
case Windows happens to use. If a rule ever genuinely needs separator-aware matching, that is the
moment to revisit — and it will be visible, because the author will be writing a `contains` whose
title does not describe it.

### `cased` reaches the new operators, and its check grew a second shape

A string operator folds ASCII case unless the field is named in `cased`, exactly as equality does
(ADR 0025). `cased` still names a **field**, so one entry covers every comparison the rule makes
against it. Two tests hold it: `a_string_in_a_list_folds_case_unless_the_field_is_cased` and
`a_text_operator_folds_case_unless_the_field_is_cased`.

ADR 0025 rejected a `cased` entry naming a field `match` does not have, because it reads as "this
field is compared exactly" while the field its author meant keeps folding. There is now a second
shape of the same mistake: naming a field `match` *does* have, but only where no text is compared —
`run_count|gte: 2`, `path|exists: true`, or an equality against a number. It reads exactly the same
way and does exactly as little, so it is rejected too, with a message that says which of the two it
is.

### What `check-rules` now refuses

ADR 0026 made it refuse a collector or a `match` field this build does not have; ADR 0027 made it
refuse an `unmeasured_when` reason the collector cannot report. Four more, in the same spirit — a
rule that is accepted and then silently evaluated as something else is the failure this line of work exists to end:

| Refused | Where | Because |
|---|---|---|
| a `\|` suffix that is not one of the eight | `rules::validate` | it would evaluate as something other than what it says, which is the whole argument against a partial Sigma |
| an empty value list, and a list where the operator has no reading for one (`gt`, `exists`) | `rules::validate` | an empty list matches nothing on any machine, for ever, and `not_found` is shown to a player as a thing looked for and not there |
| a value the **operator** cannot compare — text matching against a number, `exists` against anything but a boolean, an ordinal against a string that is not RFC 3339 | `rules::validate` | same: never a match, no warning |
| a value the **field kind** cannot take — an ordinal against a field that is only ever text, text matching against a number, a number against a timestamp field | `xtask`, via `Collector::fields` | only this build knows what a field holds. This is ADR 0026's defect arriving through the operator instead of the name |

`Collector::fields` therefore changed from `&'static [&'static str]` to `&'static [Field]`, where a
`Field` carries a name and a `FieldKind` — `Text`, `Number`, `Bool` or `Timestamp`. It is a
declaration, with ADR 0026's known limit, and it is bound to the code by a new test,
`every_emitted_value_has_its_declared_kind`, which runs every collector over every fixture host and
fails on a value whose shape is not the declared kind. A `Timestamp` is checked with
`rongroi_core::rules::is_rfc3339` — the same function the engine's ordinal comparison parses with, so
a field declared `Timestamp` is a field `|gt:` can really order.

### What did not change

`match` is still a conjunction of every entry. There is still no negation, no grouping, no named
selection and no condition expression. `allow` is untouched. `RULES_SCHEMA_VERSION` stays 1: a rule
written before this ADR parses and means what it meant, and the bundle ships inside the binary that
reads it (ADR 0004), so an old binary never meets a new rule.

## Alternatives weighed

| Alternative | Why not |
|---|---|
| Adopt Sigma's format rather than its vocabulary | A partial implementation is a format that lies: the specification says a modifier "must be supported by the backend", so a rule using one we lack means something other than it says. And nothing in Sigma expresses `Unmeasured` |
| A sibling list, `operators: {run_count: gte}`, following `cased` | A field can carry two comparisons. A map keyed on the field name holds one |
| Keep the raw `match` key as the `gaps` key and accept the loss | This is the ADR 0002 collapse, which is the defect this whole line of work exists to end |
| Compare RFC 3339 as text | Measured wrong: the collectors emit two shapes and the text order puts the later instant first |
| Path-aware `startswith` for every string field | `name|startswith: FiveM` would stop matching `FiveM.exe`. Path-aware for path fields only needs the field-kind table inside the engine, which ADR 0026 argued the engine must not have |
| Let `exists: false` take its answer from the ordinary match, like every other operator | It would be `Found` on a field nobody could read. This is the single most important line in this ADR |
| Add a general `not` while the matcher is open | `allow` is the exclusion this repository has, constrained to hash or signer so that weakening a rule is visible. A general negation is a mechanism for weakening rules quietly (`rules/AGENTS.md`, purpose boundary) |
| Add regular expressions, since Rust's `regex` has no backtracking blow-up | The cost argument is weak and the reviewability argument is not: `path|startswith: 'C:\Users\'` can be checked by eye and `(?i)users\\.*\\temp\\.*\.exe` cannot, in a tool whose output is read aloud about a person |

## What is unverified

- **No Windows machine was read.** Every statement here comes from this repository's source and its
  tests, run on macOS. Whether the paths these collectors really see have the shapes the examples
  use is not measured here; ADR 0020, 0021, 0023 and 0024 each say the same about their collector.
- **No rule in this repository uses any of these operators.** The four shipped rules are `posture`
  equalities and are byte-for-byte unaffected — `check-rules` and `check-baseline` print the same
  lines before and after this change. Everything below the syntax is exercised only by unit tests,
  never yet by a rule, a fixture under `rules/`, or a baseline host.
- **The field kinds are a declaration.** `every_emitted_value_has_its_declared_kind` proves that no
  collector emits a value of the wrong shape *on a fixture host*. A field no fixture host produces is
  unchecked, which is ADR 0026's limit inherited exactly: of the seven collectors, the four artifact
  ones are `Measured` on one baseline profile only.
- **`jiff`'s output format is pinned by observation, not by contract.** The three printed shapes in
  the table above were produced by running `jiff` 0.2.35 in this tree. A future `jiff` that always
  printed nine fractional digits would make the text comparison correct again; it would not make this
  decision wrong, and nothing here depends on the format staying as it is, because both sides are
  parsed.
- **Numbers above 2^53.** `number_ordering` compares two `i64`s, then two `u64`s, and only then falls
  back to `f64`. The fallback is reachable only for a non-integer, which no collector emits; that it
  is unreachable is reasoned from the `FIELDS` declarations, not measured.
- **Unicode.** The text operators fold ASCII case and nothing else, exactly as ADR 0025's equality
  does, with the same list of things that does not reach — non-ASCII letters, the Kelvin sign,
  expanding folds, the Turkish pair.

## Consequences

- `Rule::matcher` keeps its type, `BTreeMap<String, serde_json::Value>`, and keeps the keys as
  written. `rules::parse_match_key` is the one place that splits them, and `Rule::match_fields` is
  what every consumer uses instead of `matcher.keys()`.
- `Collector::fields` returns `&'static [Field]`. A collector added after this ADR must give each
  field a kind, and does not compile without one.
- `rongroi-core` depends on `jiff`.
- A top-level list in `match` now means **or**. It previously meant "this array equals that array",
  which no collector could produce and no rule wrote; the recursive array arm in `value_matches`
  still handles an array nested inside one, which is equally unreachable.
- The report format does not change. No snapshot moves.
