<!--
SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
SPDX-License-Identifier: CC-BY-SA-4.0
Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.
-->

# Landing page: a scan scene

**Branch:** `feat/site-scan-scene` · **Base:** `origin/dev` · **Plan:** https://claude.ai/artifact/A6Eogf2nHxSBN7LgkWgbYT
**Route:** opencode-go:A write, gemini-api:B Q0 and Q3 · **Gate:** G1 pending

## Goal

One section on the Thai and English landing pages, straight after the section "ผลมี 3 แบบ" / the three result states.
A reader watches one scan end in three kinds of evidence and no verdict, then drags a time slider and sees what
"not found" can and cannot say. With JavaScript off or reduced motion on, the finished picture simply stands.
It plays once when it comes into view and stays on its last frame, with a replay button.

## Shared contract (all three lanes hold to this)

Root: `<figure data-scan-scene>`, exactly one per page. Words live only in the HTML, as `specimen.js` does it.

| Hook | On | Meaning |
|---|---|---|
| `data-scan-source` | three source boxes | read from in the "read" beat, one direction only |
| `data-scan-row="found\|not_found\|unmeasured"` | three result rows | visible in the finished picture |
| `data-scan-jump="found\|not_found\|unmeasured"` | three `<button>` tallies, each showing 1 | go to that beat and stop |
| `data-scan-play` | `<button hidden>` | pause, play, replay; label from `data-msg-play`, `-pause`, `-replay` on the root |
| `data-scan-window` | `<input type=range min=0 max=30 value=23 hidden data-reach=16>` | 30 is today, 0 is 30 days ago, `data-reach` is the oldest day the example log still holds |
| `data-scan-window-out` | `<output hidden>` | polite live text from `data-msg-in` or `data-msg-out`, `{n}` is days ago |
| `data-scan-live` | root, set by script only | animation is running; CSS hides rows without `.scan-in` |
| `.scan-in`, `.scan-active` | row, source; set by script only | reached, being read |
| `--scan-wire` | root, set by script only | 0 to 1, progress of the read beat |

Beats, roughly: read 0–3 s, found 3–5 s, not found 5–7 s, not measured 7–9 s, then the end frame holds.

Rows, sources and copy (Thai / English). Sources: `การตั้งค่า Windows` / `Windows settings`; `Event log ของ Windows` / `Windows event log`; `เฟิร์มแวร์` / `Firmware`.

- Found: the specimen card's Secure Boot row, words as they stand on each page, from Windows settings.
- Not found: `Security log มีบันทึกว่าตัวเองถูกล้าง` / `The Security log records that it was cleared` (rule `ff967b28-984b-4de0-b361-58367ae0c2d5`), from the event log.
  Below it: `ตัวอย่าง: log นี้ย้อนได้ 14 วัน ของจริงแต่ละเครื่องไม่เท่ากัน` / `Example: this log reaches back 14 days. It differs on every PC.`
- Not measured: the specimen card's firmware row, words as they stand on each page, reason included.
- `data-msg-in`: `{n} วันก่อน: ไม่เจอในช่วงนี้` / `{n} days ago: not found in this stretch`.
- `data-msg-out`: `{n} วันก่อน: ย้อนไม่ถึง รายงานนี้บอกอะไรเรื่องช่วงนั้นไม่ได้` / `{n} days ago: out of reach. This report says nothing about that stretch.`
- Heading: `การสแกนหนึ่งรอบ` / `One scan, start to finish`. Tag: `ตัวอย่าง` / `Example`.
- Last line: `จบตรงนี้ ไม่มีคะแนน ไม่มีคำว่าผ่านหรือไม่ผ่าน คนเป็นผู้ตัดสิน` / `It ends here: no score, no pass or fail. A person decides.`

State marks use the existing `.mark-found`, `.mark-not-found`, `.mark-unmeasured`. Nothing green, no tick, no "good" colour.

## L3 · rule checks (`xtask/src/site.rs`, tests module only)

Tests that fail on today's `site/` and hold once L1 and L2 land. Each check is a helper taking text, so a control can feed it a bad string.
- **(p1)** Each page has one scene, after the three-states section, with three rows, three jumps, the tag, the last line, and a script tag for `scan.js`.
- **(p2)** Play, slider and output are `hidden` in the HTML. The slider's attributes match the contract.
- **(p3)** Both pages declare the same `data-msg-*` names on the root.
- **(p4)** Scene text holds none of: clean, safe, trusted, สะอาด, ปลอดภัย, ✓, ✔. The last line above is the one place "ผ่าน" and "pass" may appear.
- **(j1)** `site/scan.js` has the three SPDX lines, no Thai characters, and uses `prefers-reduced-motion`, `IntersectionObserver`, `visibilitychange`, `requestAnimationFrame`.
- **(j2)** `site/scan.js` holds none of: `fetch`, `XMLHttpRequest`, `WebSocket`, `EventSource`, `sendBeacon`, `Math.random`, `innerHTML`, `insertAdjacentHTML`, `eval`, `Function(`.
- **(c1, c2)** Controls: a string with `fetch(` fails j2's helper; a scene with `สะอาด` fails p4's helper.

Scope: `xtask/src/site.rs`. Non-test code stays as it is.

## L1 · the finished picture (`site/index.html`, `site/en/index.html`, `site/styles.css`)

Static markup per the contract, script tag beside the other deferred scripts, styles for the scene and its live state.
Done when: script off, the whole end frame shows and no control is visible; 375 px wide, no sideways scroll, text wraps; colours keep WCAG AA; the bright-sky look of ADR 0045 holds; rows are real text, wires may be SVG.
Out of scope: other sections, `flow.js`, `specimen.js`, `compare.js`.

## L2 · the motion (`site/scan.js`, new)

Done when: it plays once on first view and ends on the same picture as without script; one animation loop, which stops off screen, in a hidden tab and at the end frame; a fixed timeline, nothing random; reduced motion means no autoplay and no `data-scan-live`, with the slider still usable; any control a person touches stops autoplay for good until they press replay; keyboard reaches every control; a missing element leaves the page as written, with no error.
It only sets classes, the hooks above and the slider's `aria-valuetext`. It builds no markup from strings.
Out of scope: every other file. Follow the header and style of `site/flow.js`.

## All lanes

Scratch only in `$TMPDIR`. Files outside scope refuse the run. Diff at most 400 lines. No new dependency.
