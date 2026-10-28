# ADR 0088 — An anchor dated after the scan

- Status: accepted — the owner decided the four questions in "Owner questions" on 2026-10-28, each as
  recommended ("Owner decisions")
- Date: 2026-10-28
- Related: ADR 0039 (the report's time anchor), ADR 0061 (trace ages and its anchors, section 2), ADR 0073
  (a saved report; `schema` 1, additive changes), ADR 0084 decision 1 (the horizon timeline's history tag),
  AGENTS.md hard rule 3 (evidence, never a verdict)
- Amends: ADR 0061 section 2 (an anchor's `measured` state may leave out `days_before`)

## Context

The trace-ages section shows each anchor (ADR 0061 section 2) as its UTC date and the whole days between
that date and the scan. The view builds that count in `anchor_ages` (`crates/rongroi-core/src/view.rs:838-850`,
on `dev` at `582c93d`):

- an anchor's date is parsed as a `jiff::civil::Date`, the scan's date is the UTC date of the header's
  `generated_at`, and the count is `on.until(scan)` in days;
- the count goes into `AnchorAgeState::Measured { days_before: i64, .. }`
  (`crates/rongroi-core/src/view.rs:553-574`), a field that is always present;
- a date that does not parse becomes `Unmeasured { reason: read_failed }`.

**When the anchor's date is later than the scan's date, `on.until(scan)` is negative**, and the report
shows it as a number of days before the scan: "2026-01-04, -2 days before this scan". That sentence is not
true, and AGENTS.md hard rule 3 says the report shows only what it read. This is the same defect the
trace-age rows, the FiveM folder line and the cross-source line had, which `dev` fixed at `255514a`
(PR #242). Those three already held their count as `Option<i64>` and now leave it out when the time is
after the scan. The anchors could not be fixed in that change, because their field is an `i64` that is
always present, and making it optional changes what the view and a saved report hold.

How an anchor comes to be dated after the scan. The anchors are dates Windows or the file system wrote
(`InstallDate`, Windows Setup's kept installations, the change journal's identifier read as a time, the
creation dates of the system drive root, `$Recycle.Bin` and FiveM's program folders). The scan's time is
the clock at scan time. Both sides come from a clock, so a clock that was ahead when the date was written,
or is behind now, gives an anchor later than the scan. The report does not know which, and does not say.
`boot_time` is not affected: its count comes from `seconds_since_boot`, an unsigned number of seconds
(`view.rs:829-833`).

Who reads the field today:

| Reader | Where | What it does with the count |
|---|---|---|
| The CLI | `crates/rongroi-cli/src/trace_ages.rs:123-129` | `trace_ages.on` with `words.days(days_before)` |
| The desktop's trace-ages section | `apps/desktop/src/views/TraceAges.tsx:136-143` | `trace_ages.on` with `days(t, anchor.days_before)` |
| The desktop's horizon timeline | `apps/desktop/src/views/HorizonTimeline.tsx:62-71` | the history tag, `${days_before}d`, from `install_date` or else `boot_time` |
| The desktop's type | `apps/desktop/src/types.ts:96` | `days_before: number`, required |
| A saved report (ADR 0073) | `SavedRecord.view`, `crates/rongroi-core/src/view/saved.rs:122-123` | holds the SS view as it is, `schema` 1 |
| Nakara's upload parser | `nakara-city/web/src/lib/pc-check-upload.ts:54` | keeps `view` as an opaque object; does not read the count |

## Decision

### 1. `days_before` becomes optional, and is left out when the anchor's date is after the scan's date

`AnchorAgeState::Measured.days_before` becomes `Option<i64>`, with
`#[serde(default, skip_serializing_if = "Option::is_none")]`, the same shape `TraceAgeState::Measured`
already uses (`view.rs:603-607`). It is `None` when the anchor's date is later than the scan's UTC date.
An anchor dated the same day as the scan stays `Some(0)`. When the scan's own time does not parse, the
anchor stays `unmeasured { read_failed }`, as it is on `dev` today: the sentence of section 2 says the date
is later than the scan's, which the report could not know then. (Corrected 2026-10-28, before it was built:
the draft also left the count out in that case, which would have shown that sentence without a scan date.)

The anchor stays `measured`. Its date, `source` and `kept` are shown as before: the date was read, and an
anchor dated after the scan is itself something a reviewer should see. Only the count, which would be
false, is left out. It does not become `unmeasured`, which would hide a date that was read, and the count
is not clamped to 0, which would state a number the report did not measure.

`boot_time` keeps its count, always `Some`.

### 2. What each reader shows

- **The CLI and the desktop's trace-ages section** show the date with a new key,
  `trace_ages.on_after_scan`: en "{{date}}, later than this scan's own date", th
  "{{date}} (ใหม่กว่าวันที่ของการสแกนนี้เอง)". It sits beside `trace_ages.oldest_after_scan` (PR #242) and says
  the same kind of thing in the same way. No colour, icon or ranking marks it (ADR 0061, hard rule 3).
- **The horizon timeline** shows `-` as its history tag when the anchor it picks has no count, as it does
  today when neither anchor is measured. It does not fall back to `boot_time` for that reason: the choice of
  anchor stays ADR 0084 decision 1's, and a different anchor would put a different fact in the tag.
- **The desktop's type** becomes `days_before?: number`.

### 3. The schemas do not change their versions

`REPORT_SCHEMA_VERSION` is not touched: the report itself holds the anchor's date, not the count, and that
does not change. The view's JSON and a saved report's `schema` stay 1, under ADR 0073's "additive changes
keep it 1", for these reasons:

- a record written before this change always has the field, and reads back as `Some`;
- a record written after it has the field in every case but one, and in that case the old field held a
  false number;
- the one reader outside this repository, Nakara's upload parser, does not read the field.

This is the same reasoning PR #242 applied to the trace-age rows, which also leave out a count a saved
report used to hold. If the owner rules that leaving out a field is not additive (owner question 2), the
alternative is section 3 of "Alternatives weighed".

## Tests

Each is written first and fails on `dev` before the change:

1. `rongroi-core` view: an `install_date` anchor dated two days after the scan gives
   `Measured { on, days_before: None, source: Some(..), .. }`; one dated the scan's day gives `Some(0)`;
   one dated before gives the count it gives today.
2. `rongroi-core` view: the JSON of the first case has no `days_before` key, and keeps `on` and `source`.
3. `rongroi-cli`: the anchor line for the first case uses `trace_ages.on_after_scan`, and the new key is in
   `every_key_this_text_uses_is_in_both_languages`.
4. Desktop `TraceAges`: the anchor line for an anchor without a count shows the new text and no "-".
5. Desktop `HorizonTimeline`: an `install_date` anchor without a count gives the tag `-`, never
   `undefined d`.
6. The existing insta snapshots do not change: no fixture today has an anchor dated after its scan
   (searched on `dev` at `582c93d`).

## Order of work

One change, touching `crates/rongroi-core/src/view.rs`,
`crates/rongroi-cli/src/trace_ages.rs`, `apps/desktop/src/types.ts`, `apps/desktop/src/views/TraceAges.tsx`,
`apps/desktop/src/views/HorizonTimeline.tsx`, their tests, and both `report.json` locales. One PR into
`dev`, after the owner accepts this ADR. The changelog line is neutral: "An anchor dated after the scan
shows its date without a day count."

## Owner questions

1. **Shape.** Make `days_before` optional and leave it out when the anchor is dated after the scan
   (section 1)? Recommended: yes. Consequence: the anchor keeps its date, the false count is gone, and the
   field matches the trace-age rows.
2. **Schema.** Keep the view's and a saved report's `schema` at 1 (section 3)? Recommended: yes, as PR #242
   already did for the trace-age rows. Consequence of no: a new state instead (alternative 3), with the
   same `schema` question for a new state name.
3. **Horizon timeline.** Show `-` when the anchor it picks has no count (section 2)? Recommended: yes.
   Consequence of falling back to `boot_time` instead: the tag would name a younger fact than the install
   date the reviewer expects there.
4. **Wording.** en "{{date}}, later than this scan's own date" and th "{{date}} (ใหม่กว่าวันที่ของการสแกนนี้เอง)"?
   Recommended: yes, worded like `trace_ages.oldest_after_scan`.

## Owner decisions

Decided by the owner on 2026-10-28, each as recommended:

1. `days_before` becomes optional and is left out when the anchor is dated after the scan (section 1).
2. The view's and a saved report's `schema` stay at 1 (section 3).
3. The horizon timeline shows `-` when the anchor it picks has no count (section 2).
4. The wording is en "{{date}}, later than this scan's own date" and th "{{date}} (ใหม่กว่าวันที่ของการสแกนนี้เอง)".

## Alternatives weighed

| Alternative | Why not |
|---|---|
| 1. Clamp the count to 0 | States a number the report did not measure, and hides that the date is after the scan |
| 2. Make the anchor `unmeasured { read_failed }`, as an unparsable date is | The date was read; hiding it removes a fact a reviewer should see |
| 3. A new state, `after_scan { on, source, kept }` | Says the same as section 1 with a new state name every reader must learn; a reader that matches on `state` would drop the anchor |
| 4. Leave it negative and explain it in the text | The number still reads as days before the scan wherever it is shown without the text, such as the horizon tag |

## What is unverified

- How often an anchor is dated after the scan on real PCs: not measured. The trace-age rows' case showed
  in a fixture (`pca_files_present`, `-2`), not on a measured PC.
- Whether any reader of saved reports other than Nakara's parser exists: none is known.

## Consequences

- The report no longer states a false day count for an anchor.
- A reviewer sees the anchor's date and a sentence that it is later than the scan's date, with no reason
  given, since the report does not know whether the clock was ahead then or is behind now.
- The view's type changes in one field, and the desktop handles its absence in two views.
