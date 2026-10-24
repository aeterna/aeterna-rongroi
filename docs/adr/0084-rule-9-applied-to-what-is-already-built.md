# ADR 0084 — Rule 9 applied to what is already built

- Status: accepted — the owner ordered the five fixes below on 2026-10-24, each as recommended after an
  audit; the new text in the table is drafted and waits for the owner at G1; nothing is built
- Date: 2026-10-24
- Related: `AGENTS.md` hard rules 3 ("Evidence, never a verdict"), 6 and 9 ("Nothing vouches for a program,
  a file or a PC"), ADR 0009, ADR 0014 (unmatched observations), ADR 0045 (the report in layers), ADR 0060
  (what starts by itself, decision 5), ADR 0078 (programs recorded near a game session, section 4),
  ADR 0083 (withdrawn)
- Amends: ADR 0045 (the overview's words), ADR 0060 decision 5 (files under `%SystemRoot%` are checked),
  ADR 0078 section 4 (FiveM's and the game's names no longer keep a record out of the candidates), ADR 0009
  (no starter allow-list)

## Context

On 2026-10-24 the owner withdrew O1 (ADR 0083) and added hard rule 9: nothing in this program vouches for a
program, a file or a PC. The owner then asked whether anything already built does the same. An audit of
`dev` at `0a9bbec` found five things. Each was confirmed by reading the code:

1. **The overview speaks a verdict.** In `apps/desktop/src/views/HumanSummary.tsx`, when there is no
   evidence of strength `tamper` and at most five checks are unmeasured, the banner reads "No FiveM game
   file modifications or history wiping detected. Found N common observations, which are typical
   behaviors of GPU/fan software, Discord, scripts, and temp installers." The cards read "No Wiping Found"
   ("Event Logs continuous, no audit log clearing or USN truncation anomalies") and "Benign Patterns"
   ("Explainable by standard background tools and software"). In `HorizonTimeline.tsx`, the badge reads
   "Continuous History · No Wiping Detected" or "Continuous History (New OS)". Under it, the first step
   says "Event Logs recorded continuously" and the last says "Offline Sealed".
   - None of these is a measurement. A rule that is not found says "not found within what was read", and
     hard rule 3 forbids a pass/fail summary.
   - The banner's `hasProxyDll` branch looks for `"proxy"` inside a rule id, and rule ids are UUIDs, so it
     can never be true.
   - The key `glance.fivem_session_text` ("exited normally") is in the locale files and is used nowhere.
2. **The AI export asks for a verdict.** `AiExportButton.tsx` builds a prompt, written in the component
   rather than the locale files, that asks: "Does this machine reflect ordinary user patterns, or are
   there indications of game tampering, cheating, or anti-forensics?" Its opening line asks for a split
   "between benign everyday usage and suspicious or tampering indicators".
3. **A name keeps a program out of the candidates.** `view::game::gather` skips every record whose name is
   `FiveM.exe`, `GTA5.exe`, `GTA5_Enhanced.exe`, `PlayGTAV.exe` or `FiveM_b…_GTAProcess.exe`
   (`loaded_files::is_timeline_name`), whatever its path.
   - A program renamed to one of those names and run from Downloads is never a candidate. No identity
     fact is ever established for it, and it appears only as a name and a time on the timeline.
   - The names are anchors of a session (ADR 0062). Being an anchor does not need the record to be left
     out of the candidates.
4. **A folder keeps files from being checked.** The `autostart` collector neither hashes nor
   signature-checks a file under `%SystemRoot%` other than `%SystemRoot%\Temp` (ADR 0060 decision 5,
   `autostart.rs` `path_kind`). Such a file reaches the report with its path only.
   - ADR 0060 chose this for two reasons. 201 of the measured PC's 230 service DLLs there have no embedded
     signature, because Windows signs them through catalogs. And checking them took 77.5 s cold on a runner.
   - Some folders under `%SystemRoot%` can be written by an ordinary account. This was not measured here.
     A file placed there and started by a scheduled task reaches the report without the facts every other
     file gets.
5. **Hard rule 6 still invites an allow-list.** It says "`allow` entries are by hash or signer — never by
   file name", which reads as permission to list known-good software. ADR 0009 still says a rule waits
   for "a starter allow-list". One `allow` entry exists: the rule that reports a `FiveM.exe` signed with
   a certificate other than the one it knows (ADR 0036).
   - That entry names the expected certificate, so the rule reports the unexpected one. It vouches for
     nothing.
   - What an `allow` removes is still listed as unmatched, not dropped (ADR 0014).

The audit found these were not vouching:
- own traces (they are shown in both modes)
- the SS-mode filter (privacy, and counted)
- `rules/known-fps.csv` (read by CI only, never built into the program)
- I4 (a list of places that are noted, not trusted)
- the ADR 0078 ordering (it counts facts)
- L1 (ADR 0082). L1 counts loaded files outside Windows, Program Files and FiveM's folders. It
  establishes one fact, a count, and leaves out no record and no row: the files inside those folders were
  never listed in the first place (ADR 0021).

## Decision

### 1. The overview states counts, not a verdict

- The banner says what the scan lists.
  - With evidence of strength `tamper`, it keeps its tamper sentence.
  - With more than five checks unmeasured, it keeps its rights sentence.
  - Otherwise it shows the existing line "Evidence only. This report cannot prove that a PC is clean."
  - The dead proxy branch and its key are removed.
- The history card:
  - With tamper evidence, it keeps its tamper badge and text.
  - Otherwise its badge is the existing "not found" state word, and its text is a new sentence that this
    is within what was read and that how far back each source reaches is below.
- The findings card keeps its count. Its badge shows only with tamper evidence. Otherwise its text is the
  existing line "found — each one lists ordinary things that also produce it".
- The horizon timeline:
  - Its badge is the tamper badge, the rights badge, or a new neutral badge, "No log clearing found in what
    was read".
  - "Event Logs recorded continuously" becomes "Oldest event log record".
  - "Offline Sealed" becomes "This scan".
- Two English strings whose Thai already reads right change to match it:
  - The heading over a finding's causes, "Common benign causes for this result:", becomes "Ordinary things
    that also produce this:" (Thai "เรื่องปกติที่ทำให้เกิดผลแบบนี้").
  - The tamper text "Observations indicate intentional history alteration or wiping" names an intent the
    scan cannot see. It becomes a fact about the trace (Thai "พบข้อสังเกตที่มีลักษณะเป็นการลบหรือตัดทอน
    ประวัติ").
- The keys `reassurance_benign`, `reassurance_proxy`, `history_clean_badge`, `history_clean_desc`,
  `obs_benign_badge`, `obs_benign_desc`, `badge_continuous`, `badge_short` and `fivem_session_text` are
  removed.

### 2. The AI export asks for causes, not a verdict

The prompt moves into the locale files, `ai_export.prompt.*`. It asks for the ordinary causes and the
other possible causes of each observation, and for what the unmeasured checks leave unknown. It ends with
"Do not conclude that this PC is clean or that it was used to cheat: the report is evidence, not a
verdict." The machine and scan data it carries do not change, and neither does the masking of user names
and paths.

### 3. Names do not keep a record out of the candidates (amends ADR 0078 section 4)

`gather` no longer skips a record because of its name. A `FiveM.exe`, `GTA5.exe`, `GTA5_Enhanced.exe`,
`PlayGTAV.exe` or `FiveM_b…_GTAProcess.exe` record is a candidate like any other, with its facts and its
windows.
- Sessions are still found from the same records (ADR 0062). `is_timeline_name` keeps its other use, which
  is choosing whose loaded files Prefetch counts (ADR 0082).
- The genuine game and FiveM will now appear as candidates, recorded during the session (T2). That is the
  cost: about two to five more candidates on every report that has a session.
- In SS mode they are named only when an identity fact holds, as every candidate is.

### 4. Files under `%SystemRoot%` are checked too (amends ADR 0060 decision 5)

The `autostart` collector hashes and signature-checks every file it reports.
- Files outside `%SystemRoot%` keep their 30 s budget, nearest first.
- Files under `%SystemRoot%` are checked afterwards, under a second 30 s budget of their own.
- A file under `%SystemRoot%` that cannot be read, or that the second budget does not reach, does not become
  a gap of its place.
  - A place gap on `sha256` or `signature` turns every rule that asks about those fields there `unmeasured`
    when nothing matched (`engine.rs`, ADR 0044). The one rule that asks today rules out `%SystemRoot%`, so
    such a gap would hide a measured answer behind a file it never asks about.
  - Instead, the row carries a new text field, `file_unread`, holding the reason (`budget_spent`,
    `access_denied`, `read_failed`). The row says the file was not read, and no rule's answer changes.
  - Files outside `%SystemRoot%` keep today's place gaps exactly.
- A catalog-signed Windows file reads as having no embedded signature. This is a fact the row has always
  stated, and the rule's text already says so.
- The rule keeps its path condition (`program_data`, `user_profile`, `other`). Rows under `%SystemRoot%` and
  Program Files now carry the same facts as every other row in the unmatched list. A rule that narrows its
  question leaves out no row (ADR 0014).
- Which folders under `%SystemRoot%` an ordinary account can write is not measured. A rule for them waits
  for that measurement.
- The consent text changes in both programs. "where it is and, outside the Windows folder, its SHA-256 and
  signature" becomes "where it is, its SHA-256 and signature". `PRIVACY.md` changes with it.
- Every sentence that says files in the Windows folder are not checked changes with it:
  - the rule's description, in `rule.yaml` and `rules/i18n/th.yaml`, with `docs/rules-reference*.md`
    regenerated from them
  - the screenshare guides (`docs/screenshare-guide.md`, `.th.md`)
  - the fixture notes (`fixtures/hosts/PROVENANCE.md`)
- Recorded host fixtures stay as they were captured. A new capture carries the new facts.

### 5. `allow` narrows a question; it never lists good software

Hard rule 6's second sentence becomes: "`allow` may only name what a rule expects, so that the rule reports
what differs from it, by hash or certificate and never by file name. It never lists software as known
good (rule 9)." The one entry that exists does exactly that, and stays. ADR 0009's "starter allow-list" is
withdrawn by an amendment there.

The in-scope list in `AGENTS.md`'s purpose boundary says "reducing false positives (allow-listing legitimate
software by hash or signer)". It becomes "reducing false positives (narrowing what a rule asks, and naming the
ordinary causes of what it finds)".

## Text (drafted; the owner approves it at G1)

| Key | ไทย | English |
|---|---|---|
| `glance.history_not_found_desc` | ไม่พบบันทึกการล้าง log หรือการ reset change journal ในสิ่งที่อ่านได้ แต่ละแหล่งย้อนกลับไปได้ไกลแค่ไหนอยู่ด้านล่าง | No record of a log being cleared or of the change journal being reset was found in what was read. How far back each source reaches is below. |
| `horizon_timeline.badge_not_found` | ไม่พบการล้าง log ในสิ่งที่อ่านได้ | No log clearing found in what was read |
| `horizon_timeline.step_history_start_sub` | record เก่าสุดของ event log | Oldest event log record |
| `horizon_timeline.step_current_scan_sub` | การสแกนนี้ | This scan |
| `human_findings.causes_title` | (unchanged) เรื่องปกติที่ทำให้เกิดผลแบบนี้: | Ordinary things that also produce this: |
| `glance.obs_tamper_desc` | (unchanged) พบข้อสังเกตที่มีลักษณะเป็นการลบหรือตัดทอนประวัติ | A log was cleared or the change journal was reset; what came before cannot be seen |
| `ai_export.prompt.intro` | ช่วยอธิบายรายงานตรวจเครื่องจาก aeterna-rongroi v{{version}} ข้างล่างนี้ ตามข้อเท็จจริงทางเทคนิค | Please explain this PC check report from aeterna-rongroi v{{version}}, from its technical facts. |
| `ai_export.prompt.questions` | 1. ข้อสังเกตที่พบแต่ละข้อ อะไรที่เป็นสาเหตุปกติ และมีสาเหตุอื่นใดได้อีก 2. รายการที่ยังไม่ได้วัด ทำให้อะไรยังไม่รู้ 3. สรุปสั้น ๆ 3 บรรทัด อย่าสรุปว่าเครื่องนี้สะอาดหรือใช้โกง: รายงานนี้เป็นหลักฐาน ไม่ใช่คำตัดสิน | 1. For each observation, what ordinary causes produce it, and what other causes could? 2. What do the unmeasured checks leave unknown? 3. A three-line summary. Do not conclude that this PC is clean or that it was used to cheat: the report is evidence, not a verdict. |
| consent (`autostart`) | พร้อมไฟล์ที่แต่ละรายการเริ่ม — ตำแหน่ง SHA-256 และลายเซ็น (Authenticode) | with the file each one starts — where it is, its SHA-256 and signature (Authenticode) |
| rule `72820eaf` description, the sentence "Files under the Windows folder are not checked at all" | ไฟล์ในโฟลเดอร์ Windows ถูกตรวจหลังไฟล์อื่น และแสดงในรายการที่ไม่เข้า rule แต่ rule นี้ไม่ถามถึงมัน | Files under the Windows folder are checked after the others and are shown among the unmatched rows, but this rule does not ask about them. |
| screenshare guide, the same sentence | ไฟล์ในโฟลเดอร์ Windows ถูกตรวจหลังไฟล์อื่น ถ้าเวลาไม่พอจะบอกว่าไม่ได้อ่าน | Files in the Windows folder are checked after the others; one the time does not reach says it was not read. |

The data blocks of the AI prompt (machine, scan, observations, unmeasured count) keep their current
wording.

## Alternatives weighed

| Alternative | Why not |
|---|---|
| Keep the overview's words and add a disclaimer | A disclaimer under "Benign Patterns" still says "benign" first |
| Remove the overview | It is the reading layer ADR 0045 chose. Only its words are wrong |
| Keep the names out of the candidates, but check their path against FiveM's folders | The game's own folder is anywhere (Steam, Epic, Rockstar), so a path list would be one more list of good places |
| Leave `%SystemRoot%` unchecked and say so | The row already says so. The point is that a file there gets no facts at all |
| Remove `allow` from the rule format | The one entry is how a rule says what it expects. Without it, the FiveM.exe rule cannot be written |

## What is unverified

- How long the second `autostart` budget takes on an ordinary gaming PC. ADR 0060's 77.5 s was a cold
  runner with 230 service DLLs.
- Which folders under `%SystemRoot%` an ordinary account can write.
- How many genuine game and FiveM records the candidate list gains on a real report.

## Consequences

- The overview tells less at a glance and nothing it cannot back.
- Every report with a session lists the game and FiveM among its candidates.
- An elevated or standard scan may take up to 30 s longer when `%SystemRoot%` holds many autostart files.
- Snapshots of hosts with autostart files under `%SystemRoot%` gain `sha256` and `signature`. Snapshots of
  hosts with a session gain the game's candidates.
