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
  rejects the rest and names what the collector does report. Since ADR 0030 every one of the twelve
  reasons has a producer, so the check is entirely about *which* collector: `not_on_this_os` is `pca`
  alone, `service_disabled` is `prefetch` alone, `budget_spent` and `not_attempted` are `evtx` alone.
  Declaring a reason you have not thought about hides a result a reviewer should have seen.
- **`partial`, `budget_spent` and `read_failed` cannot be declared away**, and since ADR 0032 naming
  any of them is a `check-rules` failure rather than a line that changes nothing. All three say the
  artifact was reachable and the read of it did not finish — a fact about the scan, not one about a
  kind of machine that an author could have anticipated (ADR 0030, ADR 0032). `access_denied` and
  `source_absent` are the other side of that line and stay declarable: they say the program never
  reached the artifact, and why, in terms of how the machine is set up.
- **`source_absent` and `source_empty` are opposite statements.** "This PC has no such record" and
  "the record's place is there and holds nothing" were one word until ADR 0030; a rule that means one
  must not declare the other. `source_empty` in particular is **never** evidence that anything was
  removed: Windows' own scavenger empties BAM of entries older than seven days at every boot, and a
  Prefetch folder is routinely emptied by an optimiser the player ran.
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
- **An event id is unique only per provider, so never match one alone.** 1102 is a cleared audit log on
  the `Security` channel *and* an Exchange antimalware engine update in `Application` *and* an RDP client
  event; 104 is a cleared log file on `System` *and* a Remote Desktop timezone offset. Pin `provider` and
  `channel` beside the id, and give the rule a negative fixture built from the collision (ADR 0031).
- **A value list is `or` within one field, so two fields carrying one are a cross product.**
  `event_id: [1102, 104]` with `channel: [Security, System]` also asks for a 1102 on `System`. Where the
  pairs are what you mean and the cross product is not, that is two rules, not one — and two findings a
  reader can tell apart usually turn out to be the reason (ADR 0031).
- **`strength` decides whether a rule's `not_found` reaches an SS reviewer**: `posture` is listed,
  everything else is counted (`view::ss_lists`). So a rule whose negative result means almost nothing —
  a log-clearing rule, whose record a later clearing removes — must not be `posture`, or the report
  grows a row that reads as "we looked and it is clean", which is the closest this program can come to a
  verdict (ADR 0002, ADR 0031).
- `status: test` or `stable` needs a positive and a negative fixture in `tests/`. Fixtures are
  hand-written observations, so they test the engine and the predicate — **not** that a real machine
  produces the strings the rule matches. Where the matched value comes from Windows rather than from our
  own collector, and no file in this repository carries it, `experimental` is what the evidence supports
  and a fixture must not be manufactured to leave it (ADR 0031).
- A new rule must also be quiet on every `fixtures/hosts/baseline-*` host, or carry a
  `known-fps.csv` row with a reason (`cargo xtask check-baseline`, ADR 0017). **Quiet is not the same as
  measured, and for some rules the gate cannot tell you which you have.** The only Event Log sample in
  this repository is a LanguagePackSetup log, so a rule naming the `Security` or `System` channel is
  `not_found` on every baseline and the gate stays green whatever the rule says. Do not close that by
  inventing a log: a baseline asserts that a machine like it is unremarkable
  (`fixtures/hosts/PROVENANCE.md`). Say in the pull request which of your rules the gate could not
  measure (ADR 0031).
- Fixtures are synthetic observations. Never commit cheat binaries, loaders or real player data.
- **Out of scope:** rules, comments or fixtures that explain how to avoid a rule, and weakening a rule
  without a documented false-positive reason. Bypasses are reported privately via
  [`SECURITY.md`](../SECURITY.md).
- Rules, translations and fixtures in this folder are CC-BY-SA-4.0.
