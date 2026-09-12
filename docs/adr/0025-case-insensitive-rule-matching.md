# ADR 0025 — Rule matching folds ASCII case, and `cased` is the way back

- Status: proposed
- Date: 2026-09-13

## Context

`rongroi_core::engine::matches` compared a rule's `match` values to an observation's fields with
`observation.fields.get(field) == Some(expected)`. That is `PartialEq` on `serde_json::Value`, and for
a string it is byte equality.

Windows does not compare paths or file names that way. A rule written `path: "C:\\Windows\\Temp\\x.exe"`
did not match an observation carrying `C:\WINDOWS\Temp\x.exe`, and **nothing said so**. The rule reported
`not_found`, which every surface of this tool presents as a thing that was looked for and was not there,
carrying the rule's `retention` window as the measure of how far back the look reached. ADR 0002 exists
to keep `not_found` and `unmeasured` apart; a silent miss is a third thing that was being reported as the
first. It is the worst failure this tool can have, because it is wrong about a person in the direction
that reads as reassurance, and it is a correctness defect rather than a missing feature.

The collectors had already been working around it, in the code, in those words: `paths.rs` lower-cases a
file name and says *"a rule matches by exact equality and Windows does not care about the case a program
was launched with"*, and `prefetch.rs` repeats it for the Prefetch executable name. `path` is **not**
normalised — `paths.rs` says *"`path` is left exactly as the artifact spelled it"* — so every path-bearing
rule on all six collectors was exposed. Normalising on the way in is also not a fix available to every
field: the emitted value is what a reviewer reads, and lower-casing a path to make matching work would
change what the report shows a person about their own machine.

This is settled before any further matcher operator is added, because every operator — `contains`,
`startswith`, a value list, `exists` — inherits the answer to "what does it mean for two strings to be
the same here".

## Decision

### Every string in `match` folds ASCII case; nothing else changes

`matches` compares through a new `value_matches`, which folds strings with `eq_ignore_ascii_case` and
otherwise keeps `serde_json`'s equality unchanged.

**Scope is every string, not only paths and names.** The alternative was to fold `path`, `name` and their
relatives and leave `channel`, `provider`, `source`, `read` and the enum-like values exact. It was
rejected because the engine has no way to know which field is which, and giving it one means a table of
field name → comparison kind maintained somewhere — in `rules.rs`, or per collector next to the `FIELDS`
arrays. Nothing cross-references those arrays against rules today: a rule may name a field no collector
emits and be permanently `not_found` with no warning. A classification table would inherit exactly that
blind spot, and its failure mode is the one this ADR is removing — a collector gains a field, nobody adds
it to the table, the field gets whichever comparison the default is, and a rule quietly means something
other than it says. A rule with no table behind it is also a rule a contributor can hold in their head.

The cost of the blanket rule is that fields whose vocabulary is closed and lower-case — `secure_boot:
disabled`, `read: access_denied`, `intact`, `source` — now also fold, which buys nothing. It costs
nothing either: no closed vocabulary in this repository contains two values that differ only in case, so
no rule's meaning widens. If one ever does, `cased` says so in one line at the rule.

**`allow` is deliberately untouched.** `sha256` there already folded ASCII case and still does; `signer`
still compares exactly. Folding `signer` would widen an *exclusion*, which is weakening a rule, and
AGENTS.md requires a documented false-positive reason for that — there is none, and no collector in this
repository has ever emitted a `signer` field to fold. The collector id at `matches`'s first line is also
still exact: it is not an observation field but an identifier this repository chooses, and
`rules::validate_path` already requires it to be snake_case.

### ASCII, not Unicode

`str::eq_ignore_ascii_case`, which folds `A`–`Z` against `a`–`z` and leaves every other byte alone.

The reason is consistency inside this file. `SelfIdentity::describes` compares a path and a digest with
`eq_ignore_ascii_case`; `is_allowed` compares `sha256` the same way; `rules::is_uuid_v4` uses
`to_ascii_lowercase`. Unicode folding in the matcher would mean two different notions of "the same
string" in one function — a rule and the own-trace partition that runs before it could disagree about
whether two paths are the same path.

**What it does not handle**, stated rather than discovered later:

- **Non-ASCII letters do not fold.** `C:\Users\Sömchai\…` does not match `C:\Users\SÖMCHAI\…`. A Windows
  path can contain any of them, and a user folder named in Thai, Cyrillic or accented Latin is ordinary.
  A test pins this rather than leaving it to be found.
- **The Kelvin sign** (U+212A), whose Unicode lowercase is `k`, does not fold to `k` here.
- **Expanding folds** — `ß` against `SS`, `ﬁ` against `fi` — do not happen; ASCII folding cannot change a
  string's length and Unicode folding can.
- **The Turkish pair.** ASCII folding treats `I` and `i` as the same letter, which a Turkish-locale
  comparison does not, and leaves `ı` and `İ` unfolded, which it would fold. Neither is a locale-correct
  answer; this comparison has no locale, and does not claim one.

What is **not** claimed: that this matches Windows' own comparison. Windows compares file names through a
per-volume upcase table, which is not ASCII-only — that is unverified here and nothing in this repository
tests it. The honest statement is narrower: ASCII folding is the more conservative of the two available
folds, it is what the rest of this file already does, and it turns the whole class of
`C:\WINDOWS` vs `C:\Windows` misses — which is the class that actually occurs — into matches. Where it
does not reach, the result is the behaviour that shipped before this ADR, never a new wrong match.

### Numbers, booleans and null are untouched, explicitly

`value_matches` has an arm that hands everything that is not a string back to `serde_json`'s own
equality, with a comment saying so, because a reader arriving after this change will ask. `1102` does not
match `"1102"`, `1102` does not match `1102.0`, and `true` does not match `"true"` — before this ADR and
after it. Case folding is a property of text; a number has no case, and a matcher that coerced one into
the other would let a rule say something its author did not write. Arrays and objects recurse, so that
"strings in a rule fold" is true of every string in a rule and not only the top-level ones; no collector
emits either shape today, and an object's **keys** compare exactly, as the `match` field names
themselves do.

### The opt-out is per field, named `cased`, and absence means folding

A rule may carry `cased: [<field>, …]`, a list of `match` field names compared byte for byte.

**Per field, not per rule**, because case-sensitivity is a property of the field's source vocabulary and
not of the rule. One `match` block can name a `path` (which the file system folds) and a digest or an
identifier that a reviewer wants exact. A per-rule switch forces the author to either split the rule in
two or apply exactness to a path as collateral — which puts the silent miss back, one rule at a time.
Sigma reaches the same shape for the same reason: `cased` is a field modifier there, and the name is
taken from it deliberately so a reviewer who knows Sigma reads ours on sight.

**A list beside `match`, not a `path|cased:` key suffix.** Sigma writes its modifiers into the key. Here
the `match` keys are used directly: as the lookup into `observation.fields`, and — this is the part that
decides it — as the keys of the `gaps` lookup in `evaluate_rule`, which is what turns "nothing matched"
into `unmeasured` instead of `not_found`. A key carrying a `|cased` suffix would no longer equal the
field name, so a `cased` field would stop being found in `gaps` and a field the collector could not read
would report as `not_found`. That is precisely the collapse ADR 0002 forbids, arriving through the back
door of a syntax choice. A separate list leaves every key a field name.

**Absence is the safe behaviour.** A contributor who has never heard of this feature writes no `cased`
line and gets case-insensitive matching. The opt-out is the thing you have to know about, not the fix.

`check-rules` rejects a `cased` entry that names a field `match` does not have. Such an entry is not
inert: it reads as "this field is compared exactly" while the field its author meant keeps folding — the
same gap between what a rule says and what it does that the rest of this ADR closes.

### What this does to `gaps`

Nothing, and that is a decision rather than an accident. The gap lookup in `evaluate_rule` is keyed on
`rule.matcher.keys()` — field **names**. Case folding changes how values compare and adds no key, removes
no key and renames none, so exactly the same rules are reached by exactly the same gaps as before, with
or without `cased`. Every operator added after this one has to answer the same question in its own ADR:
a `gaps` behaviour that falls out of an implementation defaults to "treat it as no match", and that is
the `unmeasured → not_found` collapse.

### The four shipped rules

All four match one string field against a closed, lower-case vocabulary — `secure_boot: disabled`,
`test_signing: enabled`, `hvci: disabled`, `tpm: absent` — and the values the `posture` collector emits
are lower-case string literals in `posture.rs`. **No shipped rule changes what it matches**, on its own
fixtures or on either baseline host. Their negative fixtures differ from the positive ones by word
(`enabled` against `disabled`, `present` against `absent`), never by case, so none of them starts
matching. `check-rules` and `check-baseline` pass for the same reason they passed before, and their
output is unchanged line for line.

### Alternatives weighed

| Alternative | Why not |
|---|---|
| Leave matching exact; normalise every string in the collectors | `path` is emitted to be read by a person. Lower-casing it to make the matcher work changes what the report shows about someone's machine, and it cannot be applied to fields a future collector has not been written yet |
| Fold only `path` and `name` | Needs a field-classification table nothing maintains, whose failure mode — a new field, an un-updated table, a rule that quietly means something else — is the defect this ADR removes |
| Unicode `to_lowercase` / full case folding | Two notions of string equality inside one file, next to `SelfIdentity::describes` and `is_allowed`, which fold ASCII. Brings 1:many expansions and locale traps with no test in this repository behind them |
| Per-rule `cased: true` | Forces exactness onto a path in the same rule, which reintroduces the silent miss |
| Sigma's `path|cased:` key syntax | The key stops equalling the field name, so the field falls out of the `gaps` lookup and an unreadable field reports `not_found` (ADR 0002) |
| Make case-insensitivity opt-**in** | The contributor who does not know the feature exists gets the broken behaviour, which is how this defect reaches a report in the first place |

## What is unverified

- **No Windows machine was read.** Every statement here is from this repository's source and its tests,
  run on macOS. That Windows would in fact match `C:\WINDOWS\Temp\x.exe` to `C:\Windows\Temp\x.exe` for
  the artifacts these collectors read is background reasoning, not a measurement taken here.
- **No claim is made that this equals Windows' comparison.** NTFS's per-volume upcase table is not
  ASCII-only and is not modelled, consulted or tested here. Where the two differ, this comparison is the
  narrower one, which means a miss and never a false match — but "narrower" is reasoned from
  `eq_ignore_ascii_case`'s definition, not verified against a volume.
- **The Unicode traps listed above were not all executed.** The non-ASCII limit is pinned by a test over
  `Ö`/`ö` and a Thai path; the Kelvin sign, `ß`/`SS` and the Turkish pair are named from the definition of
  ASCII folding and have no test of their own, because the behaviour they describe is "these are not
  folded", which is what the general arm already asserts.
- **No rule in this repository uses `cased`, and none uses a non-string `match` value.** Both paths are
  covered only by unit tests in `engine.rs`; neither is exercised by a shipped rule, a fixture under
  `rules/`, or either baseline host.
- **Arrays and objects in a `match` value are unreachable in practice.** No collector emits either, so
  the recursive arms are exercised only by the code that was written with them.

## Consequences

- `Rule` gains `cased: BTreeSet<String>` with `#[serde(default)]`. `RULES_SCHEMA_VERSION` stays at 1: a
  rule written before this field existed reads back with none, which is what it meant, and the format is
  the same argument `unmatched` and `own_traces` used for the report schema.
- `engine::matches` is no longer an `Option` comparison. A rule field the observation does not carry is
  still not a match, with `cased` and without it, and a test holds that rather than leaving it to the
  shape of the expression.
- Every existing rule keeps its behaviour, every fixture keeps passing, and no report snapshot moves.
- A rule that was silently missing a differently-cased path will now match it. Nothing in the tree is in
  that state today — there is no path-bearing rule yet — so this ADR changes no report. It changes what
  the next rule can be trusted to do, which is the point of landing it before the next rule.
- The vocabulary is Sigma's: `cased` means there what it means here. If more operators follow, they take
  Sigma's names too, and each one writes down its own `gaps` behaviour in its own ADR.
