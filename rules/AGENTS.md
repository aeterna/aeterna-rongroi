# AGENTS.md — rules

Adds to the root [`AGENTS.md`](../AGENTS.md); read that first. Authoring guide:
[`docs/rules-authoring.md`](../docs/rules-authoring.md).

- A rule describes **evidence to show**, never a verdict. No scores, no "clean" rules.
- `falsepositives` must honestly list what legitimately produces the evidence. It is **shown to the
  reader** beside every `found` row, in their language (ADR 0027) — a finding shown without its
  alternatives is a finding shown as an accusation. `description` is shown beside every row whatever
  the state, so its "what this does not prove" clause is written for the reader, not for a maintainer.
- `unmeasured_when` decides what an SS view lists: a reason named there is **counted**, one that is not
  is **listed**, because an undeclared reason means something the author did not anticipate stopped the
  measurement (ADR 0027). Every entry must be a reason that collector can report — `check-rules`
  rejects the rest, including `not_on_this_os` and `service_disabled`, which nothing in this build
  produces. Declaring a reason you have not thought about hides a result a reviewer should have seen.
- `allow` identifies legitimate software by `sha256` or `signer` only — never by file name.
- **`match` compares strings without regard to ASCII case.** `path: "C:\\Windows\\Temp\\x.exe"` matches
  `C:\WINDOWS\Temp\X.EXE`, because Windows does not care which case a path was written in and a rule that
  missed one would report `not_found` — a thing looked for and not there. Non-ASCII letters are **not**
  folded: `Sömchai` does not match `SÖMCHAI`. Numbers, booleans and null are compared exactly, so
  `event_id: 1102` never matches the text `"1102"` (ADR 0025).
- **A `match` key may carry an operator**, written `field|operator` (ADR 0029). The whole vocabulary, with
  examples, is in [`docs/rules-authoring.md`](../docs/rules-authoring.md#the-operators):

  | Written | Means |
  |---|---|
  | `event_id: [1102, 104]` | a list is **or** — any one of them |
  | `run_count\|gte: 2` · `gt` · `lt` · `lte` | ordered; on numbers, and on timestamps, which are **parsed** and not compared as text |
  | `path\|startswith:` · `endswith` · `contains` | text begins with / ends with / holds text |
  | `path\|exists: true` or `false` | the field is there, or is not — which is not the same question as equality |

  `match` is still every entry at once: no `or` between entries, no grouping, no negation, no regular
  expressions, no wildcards inside a value. `check-rules` rejects an operator name that is not one of
  these, an empty list, a list where the operator has no reading for one, and an operator the field's own
  kind cannot take — an ordinal comparison against a field that is only ever text, for one.
- **`startswith` and `contains` are text, not paths.** Neither knows what a directory separator is, so
  `path|startswith: 'C:\Users\Public'` also matches `C:\Users\PublicRecords\x.exe` and
  `path|contains: 'Temp'` matches `C:\Program Files\TempleOS\game.exe`. **Put the separators in the value**
  — `'C:\Users\'`, `'\AppData\Local\Temp\'`, `'.exe'` — and read the rule's `title` back against what you
  wrote. A rule that matches more people than its title claims is the failure this repository cares most
  about (ADR 0029).
- **A field the collector could not read makes the rule `unmeasured`, under every operator**, `exists:
  false` included — there the gap is checked before anything is matched, because a field nobody could read
  is also a field that is not there, and the rule would otherwise be `found` and the report would say "we
  looked and it is not there" about it (ADR 0002, ADR 0029).
- To compare one field byte for byte, list its name in `cased`. It is per field, so the rest of `match`
  keeps folding, every field left out of it folds, and one entry covers every comparison the rule makes
  against that field, `startswith` and `contains` included. A rule with no `cased` line is
  case-insensitive — write one only when the field's own vocabulary distinguishes case, and say in a `#`
  comment why. A `cased` entry naming a field `match` does not have, or one `match` compares no text of,
  fails `cargo xtask check-rules`.
- `collector` must be a collector in this build and every `match` field name one that collector
  declares it can emit (`Collector::fields`, ADR 0026). A misspelling is not a quiet mistake: the rule
  becomes `not_found` on every machine, which this program shows a player as evidence that something
  was looked for and was not there. `check-rules` rejects it and names the field it meant.
- **Co-occurring tamper signals are not corroboration — in this population they point the other way.** A
  popular gaming "optimiser" script clears every event log on the machine in one click *and* wipes the
  Prefetch folder, so a cleared log, a burst of log-cleared events and an empty Prefetch folder arrive
  together on a PC whose owner did nothing wrong. The `evtx` collector reports a log's own state beside its
  records — `oldest_record_time`, `oldest_record_id`, `newest_record_time`, `newest_record_id`,
  `size_bytes`, and per folder `logs_without_records` and `channels` — so that a rule can match on the log
  rather than on one event. Each of those has an innocent explanation written down in ADR 0028; a rule that
  uses one must name that explanation in `falsepositives`. **A high `logs_without_records` is evidence for
  the optimiser explanation**, never for a clearing. Do not derive a gap in the record ids from the two id
  fields: an exported log is renumbered from 1, so a gap cannot be told apart from "the player exported the
  log to send it to you" (ADR 0028).
- `status: test` or `stable` needs a positive and a negative fixture in `tests/`.
- A new rule must also be quiet on every `fixtures/hosts/baseline-*` host, or carry a
  `known-fps.csv` row with a reason (`cargo xtask check-baseline`, ADR 0017).
- Fixtures are synthetic observations. Never commit cheat binaries, loaders or real player data.
- **Out of scope:** rules, comments or fixtures that explain how to avoid a rule, and weakening a rule
  without a documented false-positive reason. Bypasses are reported privately via
  [`SECURITY.md`](../SECURITY.md).
- Rules, translations and fixtures in this folder are CC-BY-SA-4.0.
