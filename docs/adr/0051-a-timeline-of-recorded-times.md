# ADR 0051 — A timeline of the times a report already holds

- Status: proposed
- Date: 2026-09-16

## Context

A report holds many times, and none of them is shown beside another:

- `last_run` from `prefetch`, `bam` and `pca`;
- `first_seen` and `last_seen` from `evtx` and `usn`, and `oldest_record_time` / `newest_record_time` for
  each log;
- the report's own `generated_at` and `boot_time` (ADR 0039);
- the times ADR 0050 would add to a directory listing, once a collector emits them.

A reviewer who asks "when was the game last started", "when did this cache go", or "does this log reach back
further than the journal" has to find each value in a different collector's rows and order them in their
head. The owner asked, on 2026-09-16, for a view that lines them up.

Four facts of the current design shape the answer.

1. **SS mode lists evidence, not observations.** `view::ss_lists` admits `found` rows, `not_found` rows of
   posture rules, and unexpected `unmeasured` rows. Every unmatched observation is counted and none is
   listed (ADR 0014). A time carried only by an unmatched observation — every `last_run` today — never
   reaches a reviewer.
2. **No rule may pick out a program on `prefetch`, `bam` or `pca` by name** (ADR 0034). Those records carry
   a name and no identity, so a rule cannot exclude legitimate software, and a rename defeats it.
3. **`rongroi-core` does not know which fields are times.** `Collector::fields` declares each field's kind
   (ADR 0026), but it lives in `rongroi-collectors`, which depends on `rongroi-core`, not the reverse. The
   engine recognises an RFC 3339 value by its shape only when a rule compares it (ADR 0029).
4. **Every row carries its ordinary causes** (ADR 0027), and the report never states a verdict (ADR 0002).
   A timeline is a place where an order of events suggests a story; it has to say what it does not show as
   plainly as a row does.

## Decision

### 1. The timeline is a view, computed in the core

`rongroi_core::view` gains `timeline(report, mode) -> Timeline`. It changes nothing that is measured and adds
no evidence. Each entry is one time value:

```text
TimelineEntry {
  at,                 // the timestamp, RFC 3339 UTC
  collector, field,   // where it came from, e.g. prefetch / last_run
  place,              // the observation's discriminator value when the collector declares one (ADR 0044)
  source,             // evidence(rule_id) | selector(selector_id) | observation
  subject,            // the observation's name or path, redacted as the row it came from is
}
```

Entries are ordered by `at`, oldest first, with ties kept in collector order (`grouping.ts`'s
`COLLECTOR_ORDER`, moved into the core). `generated_at` and a measured `boot_time` are anchors in the same
list, marked as the scan's own.

**Coverage bands.** Beside the entries, the timeline carries, per source that has one, the span it could see:
each log's `oldest_record_time`..`newest_record_time`, the journal's `first_seen`..`last_seen`. A reviewer
reads "nothing in this span" only inside a band, and the view says so above the list. A source whose run was
unmeasured shows its reason instead of a band, including the scope reasons (`not_admin`) that ADR 0027 lifts
out of the rows. Today the `usn` collector's `not_admin` reaches no output at all: `ScopeNotes` counts
rule evidence, and no rule reads `usn`. The band is where it first appears.

### 2. The report says which fields are times

`scan::run` copies, from each collector's `fields()`, the names whose kind is `Timestamp` into a new
report field, `timestamp_fields: BTreeMap<collector, Vec<field>>`. It is additive, as `own_traces`,
`unmatched` and `expected` were, and `REPORT_SCHEMA_VERSION` stays at 1. A report written before this
ADR has none and shows no timeline. The core does not guess a time from a value's shape.

### 3. Self mode: every time value

Self mode's timeline holds every timestamp field of every evidence observation and every unmatched
observation, with the anchors and bands. It shows what Self mode already lists, in another order.

### 4. SS mode: listed evidence plus reviewed timeline selectors

SS mode's timeline holds:

- the times in the evidence SS mode already lists, redacted as those rows are;
- the anchors and bands;
- **timeline selectors**: times from observations that a reviewed timeline selector in the rules bundle
  selects.

A **timeline selector** is a rule file with `role: timeline` (rule format version 4). It has everything a rule
has: `match` and `match_lists`, `description`, `falsepositives`, `references`, positive and negative fixtures,
and translations. The only difference is that a timeline selector never produces a `found`, `not_found` or
`unmeasured` row and is never counted in `ListedCounts` or `HiddenCounts`. Its matches become timeline
entries, in both modes, each shown with the selector's text and ordinary causes. The observations a timeline
selector selects stay unmatched for ADR 0014's purposes, so SS mode's hidden count does not change.

The first timeline selectors proposed, each a separate file with its own review:

| Timeline selector | Selects | Ordinary causes it must state |
|---|---|---|
| FiveM or GTA V recorded as run | `prefetch` / `bam` / `pca` entries whose `name` is one of a fixed list of the executables FiveM and GTA V ship | Any program of that name; Windows keeping a record after the files were removed; a record being absent because Windows did not write or keep one |
| Time a watched folder's journal records were written | `usn` per-folder `first_seen`/`last_seen` | FiveM, Windows and updaters create and delete files in these folders in ordinary use; the journal covers a short span |
| A log's oldest and newest record | `evtx` per-log times | Log size limits overwrite old records; a new installation; a log that a program cleared |

### 5. ADR 0034 is narrowed, not reversed

A timeline selector may select `prefetch`, `bam` and `pca` observations by `name`. That is what ADR 0034
decision 1 forbids for rules. Of the reasons ADR 0034 gives, one does not apply to a timeline selector and the
other is stated instead of hidden:

- A timeline selector makes no `found` row, so no name-based claim is presented as evidence. Its text says
  "Windows recorded a program named …", never "FiveM ran".
- A rename defeats a timeline selector as it defeats a rule. A selector's `falsepositives` must say so, and
  the timeline says, above the list, that an absent entry is not evidence that nothing ran.
- ADR 0034 decision 2 promised that SS mode would not list these observations, because that is what the SS
  consent screen said. Timeline selectors change that promise. The consent question and `PRIVACY.md` must
  name, in the same change, that SS mode shows the times Windows recorded for the programs the timeline
  selectors list — the list itself, not a description of it.

Decision 1 still holds for rules: no `role: evidence` file on these collectors may select by name or path.
`check-rules` gains that check, closing the "no gate enforces this" note in ADR 0034.

### 6. What the timeline never says

- No gap between two entries is called a gap, a cleaning or a missing period. The view prints the entries
  and the bands, and a sentence above them: an order of recorded times is not an order of events, and a
  record that is absent was not necessarily removed.
- No count, colour or summary is computed from the entries.
- Times from ADR 0050's listings carry that ADR's statement of what file times are.

## Alternatives weighed

| Alternative | Why not |
|---|---|
| A timeline in the desktop UI only | Filtering and redaction belong in the core (AGENTS.md hard rule 5); the CLI and `--json` would not have it. |
| Recognise timestamps by their shape | A text field that happens to hold an RFC 3339 string would become a time; the declared kind already exists. |
| An allow-list of `(collector, field, place)` compiled into the core | Reviewed less visibly than a rule file, with no fixtures and no ordinary causes beside it. |
| A `context` rule that names FiveM's executables | Produces a `found` row in SS mode for every player who has played, which ADR 0034 and ADR 0027 both rule out. |
| Show every unmatched time in SS mode | Undoes ADR 0014 and the SS consent screen for every program on the PC, not only the game. |

## What is unverified

- Whether the executables FiveM and GTA V ship keep stable names across builds. Names seen on one Windows 11
  PC in Prefetch on 2026-09-16 include `FIVEM.EXE`, `FIVEM_B<build>_GTAPROCESS.EXE`, `GTA5.EXE`,
  `GTA5_ENHANCED.EXE` and `PLAYGTAV.EXE`; the build number in one of them changes with the game build, so the
  timeline selector needs a pattern, not only a list.
- How long a timeline gets on an ordinary PC in Self mode. A Prefetch file carries up to eight run times,
  and an ordinary PC holds hundreds of them; the desktop layer needs a filter by collector and place before
  it is usable, and that is not designed here.

## Owner decisions this ADR needs

1. Timeline selectors as rule files (section 4), or another form.
2. The ADR 0034 narrowing (section 5), and the SS consent text that goes with it.
3. The first timeline selector list.

## Consequences

- `rongroi-core`: `Timeline`, `TimelineEntry` and `view::timeline`; `Report.timestamp_fields`; rule key `role`
  (`evidence`, the default, or `timeline`); `RULES_SCHEMA_VERSION` 4; the engine routes timeline selector
  matches to the timeline; collector order moves from `apps/desktop/src/grouping.ts` into the core.
- `rongroi-collectors`: `scan::run` fills `timestamp_fields`.
- `xtask`: `check-rules` validates `role`, and refuses a `role: evidence` on `prefetch`, `bam` or `pca` that
  matches `name` or `path`; `check-baseline` confronts timeline selectors like rules; `rules-reference` lists
  timeline selectors in their own section.
- CLI and desktop show the timeline; the desktop adds it as a layer beside the rows (ADR 0045).
- Consent text, `PRIVACY.md`, `docs/architecture.md` and ADR 0034 are updated in the change that ships the
  first timeline selector.
- `CONVENTIONS.md`'s glossary gains **timeline**, **timeline selector**, **anchor** and **coverage band** in
  the change that introduces the types.
