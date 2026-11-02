# ADR 0093 — Presenter mode and a Sources drawer for the report

- Status: proposed — drafted with the code in the pull requests that add it; the owner reads it at review
- Date: 2026-11-02
- Related: ADR 0014 (SS mode lists nothing it did not need to), ADR 0052 (what the player agreed SS mode may show),
  ADR 0061 (retention of a source), AGENTS.md hard rules 3, 5 and 9

## Context

In screenshare (SS) mode an admin walks a player through the report. The technical view is a long page of result
groups, one per collector. Two things are missing: a way to move through the page one group at a time with the
keyboard while the audience follows, and a quick answer to "where does this result come from?" for one row.

Both are easy to build in a way that breaks a hard rule. Moving the audience's eye to one group by hiding or
greying the others makes the others look unimportant or cleared (rules 3 and 9). A drawer that fetches or
computes something new could show a field SS mode filtered out (rule 5).

## Decision

### 1. Presenter mode (E10)

- SS mode, technical view only. A toggle in the report toolbar; off by default; local to the report window, not
  saved.
- Arrow keys, Page keys, Home and End move a "current group"; Escape turns the mode off. Keys are ignored while
  focus is in a form control or while the command palette is open.
- **Dim, never hide.** The groups that are not current stay in the DOM, in tab order, selectable and readable
  (opacity not below 0.6; no blur, no grey-scale, no `inert`, no `aria-hidden`). Which group is current depends on
  position only. It never depends on a row state, a rule, a publisher or any list of known names, and the current
  group gets no colour that means good or bad.
- A live region and a visible counter say "group N of M" and the group's title, so the position is not carried by
  dimming alone.
- The mode adds no data and changes no result.

### 2. Sources drawer (E11)

- A "Source" button on an evidence row opens a drawer from the right for that row only.
- The drawer shows what the row already holds as props: rule id, collector, retention text and the code links
  through the existing code-link component. No fetch, no new field, nothing about other rows. In SS mode that is
  exactly what the row already shows, so the privacy filter in `rongroi-core::view` stays the only place that
  decides (rule 5).
- Not modal: no backdrop, no `inert` on the report, no focus trap. Escape and a close button close it, and focus
  returns to the button. One drawer at a time.
- The existing "layers" section of the row is unchanged.

### 3. Motion

Both features animate `transform` or `opacity` only, inside `prefers-reduced-motion: no-preference`; with reduced
motion the final state appears at once. Animation is decoration (the page-change cross-fade of E4 follows the same
rule and needs no ADR of its own).

## Consequences

- A screenshare can follow the report group by group without any group being removed from view.
- The drawer repeats data that is already on the row; its value is reach, not new information.
- New strings live in the locale files (th, en).

## What is unverified

Not seen on a Windows screen or with a screen reader at the time of writing; the tests run in jsdom.
