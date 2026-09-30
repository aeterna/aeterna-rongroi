# ADR 0059 — What Code Integrity and Microsoft Defender already record

- Status: accepted — the owner decided the five questions below on 2026-09-30
- Date: 2026-09-30

## Context

Two of Windows' own logs keep a record of things a reviewer asks about after the fact, and the `evtx`
collector already reads both of them on every scan:

- **Code Integrity** writes an event when Windows refuses to load an executable, a DLL or a driver whose
  signature does not meet what is required of it. That is as close as this program can come to "something
  tried to load into a process and was stopped" without reading memory, which it does not do.
- **Microsoft Defender Antivirus** writes an event when it detects something, when it acts on it, and when
  its real-time protection is switched off.

Nothing new has to be read. `evtx` counts every log's records into groups of
`(log, channel, provider, event_id, level)` with a `count`, a `first_seen` and a `last_seen` (ADR 0024), and
Self mode already lists those groups as unmatched observations and puts their times on the timeline
(ADR 0014, ADR 0051). What does not exist is a rule, so an SS reviewer sees none of it.

Three limits come with the source and are not changed here:

- **No payload.** ADR 0018 drops `EventData` and `UserData` in the parser. A rule sees how many events of a
  kind a log holds and when the first and last were written, never which file was blocked, which process
  asked, what Defender detected or where. Widening that is a new ADR, not a rule.
- **An event id means something only with its provider and channel** (ADR 0031). Each rule below pins all
  three.
- **The log is the retention window.** A record rotates out when its log is full, and a cleared log holds
  none, so a `not_found` says little about the past.

## Measured

### What Microsoft documents

Read on 2026-09-30.

**Code Integrity**, channel *Applications and Services Logs → Microsoft → Windows → CodeIntegrity →
Operational* ([Understanding App Control event IDs](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/event-id-explanations)):

| Id | What the page says |
|---|---|
| 3033 | "may occur with or without an App Control policy present"; "often means the file's signature is revoked or a signature with the Lifetime Signing EKU has expired"; also "if code compiled with Code Integrity Guard (CIG) tries to load other code that doesn't meet the CIG requirements" |
| 3077 | "the main App Control block event for enforced policies. It indicates that the file didn't pass your policy and was blocked" |
| 3089 | signature information for a blocked file, one per signature, correlated with 3004, 3033, 3034, 3076 and 3077 |
| 3004 | "may occur with or without an App Control policy present. It typically indicates a kernel driver tried to load with an invalid signature" |

And, from [Microsoft recommended driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules):
"Since the Windows 11 2022 update, the vulnerable driver blocklist is enabled by default for all devices",
and it is also enforced when memory integrity, Smart App Control or S mode is on. **So a Windows 11 PC
carries an enforced App Control policy nobody installed**, and a 3077 does not mean somebody set one up.
Which policy wrote a given 3077 is in its payload, which this program does not read.

**Microsoft Defender Antivirus**, channel *Applications and Services Logs → Microsoft → Windows → Windows
Defender → Operational*, example channel name `Microsoft-Windows-Windows Defender/Operational`
([Microsoft Defender Antivirus event IDs and error codes](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus)):

| Id | Symbolic name | Message |
|---|---|---|
| 1116 | `MALWAREPROTECTION_STATE_MALWARE_DETECTED` | "The antimalware platform detected malware or other potentially unwanted software." |
| 1117 | `MALWAREPROTECTION_STATE_MALWARE_ACTION_TAKEN` | "The antimalware platform performed an action to protect your system from malware or other potentially unwanted software." |
| 5000 | `MALWAREPROTECTION_RTP_ENABLED` | "Real-time protection is enabled." |
| 5001 | `MALWAREPROTECTION_RTP_DISABLED` | "Real-time protection is disabled." |
| 5007 | `MALWAREPROTECTION_CONFIG_CHANGED` | "The antimalware platform configuration changed." |

The page does not say whether Defender writes 5001 when another antivirus product registers and Defender
steps aside. **Unverified.**

### A Windows 11 PC (build 26220), 2026-09-16

From the M4 planning measurement, read-only, counts only, elevated:

| Channel | Counts |
|---|---|
| CodeIntegrity/Operational | 3033: 200 · 3077: 23 · 3089: 252; the log was at its 1 MB cap and reached back about six weeks |
| Windows Defender/Operational | 1116: 9 · 1117: 4 · 5001: 0 · 5007: 421 |

That PC is in everyday use and runs FiveM; nothing about it is known to be unusual. **So a rule that fires
on a 3033 or a 3077 fires on it**, and on whatever else this PC shares with a player's.

### Two GitHub-hosted runners, 2026-09-30

Workflow run 36698954370, from a throwaway branch deleted afterwards, on `windows-2025` (Windows Server 2025
Datacenter, build 26100) and `windows-2022` (Windows Server 2022 Datacenter, build 20348). Each job first
read the two channels with `Get-WinEvent` before anything else ran, then built this repository's CLI from
`dev` and ran `scan --json` elevated. Only counts, ids, levels, times and channel configuration were
printed.

| | `windows-2025` | `windows-2022` |
|---|---|---|
| CodeIntegrity/Operational | enabled, circular, 1 052 672 bytes max, 93 records back to 2026-09-05 | enabled, circular, 1 052 672 bytes max, 41 records back to 2026-09-06 |
| 3033 (level 2) | **0** | **4**, on one day (2026-09-21), before the job started |
| 3077 | 0 | 0 |
| 3004 (level 2) | 1, a minute after the job's VM booted, before the probe step | 1, likewise |
| Windows Defender/Operational | enabled, circular, 16 777 216 bytes max, 551 records back to 2026-09-05 | enabled, circular, 16 777 216 bytes max, 375 records back to 2026-09-06 |
| 1116 / 1117 | 0 / 0 | 0 / 0 |
| 5001 (level 4) | **1**, 2026-09-22 | **1**, 2026-09-20 |
| 5007 | 526 | 347 |
| Defender now | real-time protection **off**, `DisableRealtimeMonitoring` set by preference, no policy key | the same |
| `VulnerableDriverBlocklistEnable` | 1 | not set |

**What this code emits for them**, from the same runs:

- `provider: Microsoft-Windows-CodeIntegrity`, `channel: Microsoft-Windows-CodeIntegrity/Operational`;
- `provider: Microsoft-Windows-Windows Defender`, `channel: Microsoft-Windows-Windows Defender/Operational`;
- the ids and levels above, with counts that agree with `Get-WinEvent` on every row.

So, unlike the log-clearing rules when ADR 0031 wrote them, **the strings the rules below match have been
produced by this code from real bytes**, on two machines.

**The 5001 on each runner is the image's.** Both carry `DisableRealtimeMonitoring` as a preference, and the
one 5001 in each log is dated eight and ten days before the VM booted, so it was written while the image
was prepared and shipped inside it. A machine whose maker switched
real-time protection off before anyone used it writes the same record a person does.

**Reaching the logs.** Both scans read every log without spending the 30-second budget (218 of 218 and 202
of 202 examined; each whole scan, a debug build, took 36 s and 26 s). In the collector's order the
CodeIntegrity log is about the 35th file and the Defender log about the 180th, with 74–80 MB of logs read
before it. The order does not change a rule's answer: a log the budget did not reach gaps every `evtx`
field, so every `evtx` rule is `unmeasured / budget_spent` and listed (ADR 0024, ADR 0032). Where the two
logs fall on a PC with twice the logs is in the next section.

### Measured on a Windows 11 PC (2026-09-30)

The probe described at the end of this ADR, run once elevated on a Windows 11 PC (build 26220) — the same PC
as the 2026-09-16 measurement — with the owner's permission. It printed counts, ids, levels, times, shapes
and settings only.

**Code Integrity.** Enabled, circular, 1 052 672 bytes max and at that size, 1 204 records back to
2026-09-09 — three weeks. Provider and channel as recorded match what this code emits on the runners.

| Id, level | Count | Days | What the probe grouped them by |
|---|---|---|---|
| 3033, 2 | 476 | 15 of the 22 | 420: a `.dll` under `Program Files` refused to a process under `Program Files`; 56: a `.dll` under `System32`/`SysWOW64` refused to a process elsewhere under `Windows` |
| 3077, 2 | 17 | 7 | all 17: a `.sys` under `System32`, policy name `Microsoft Windows Driver Policy` |
| 3023, 2 | 17 | 7 | the same times as the 3077s: the driver-side record of the same refusals |
| 3089, 4 | 511 | — | signature records for the above |
| 3004, 2 | 1 | 1 | — |

Settings beside them: `VulnerableDriverBlocklistEnable` 1; memory integrity's configured `Enabled` 1; Smart
App Control (`VerifiedAndReputablePolicyState`) 0, off.

So on this PC **every 3077 was a driver refused by a Microsoft driver policy**, with the blocklist and memory
integrity both on and no App Control policy anybody installed; and **nine in ten 3033s were one installed
program refusing a DLL of another installed program**, both in `Program Files`, on two days out of three.
That `Microsoft Windows Driver Policy` is the name the vulnerable driver blocklist carries is not stated on
the pages read; it is the only driver policy those pages say Windows turns on by default. **Unverified.**

**Defender.** Enabled, circular, 16 777 216 bytes max, 3 215 360 bytes used, 2 821 records back to
2026-08-01 — two months in a fifth of the log. Real-time protection on, tamper protection on; Security Center
lists one antivirus product, Defender.

| Id, level | Count | Days |
|---|---|---|
| 1116, 3 | 9 | 1 (2026-08-30), within one minute |
| 1117, 4 | 4 | the same minute |
| 5001 | 0 | — |
| 5007, 4 | 582 | — |

Defender's own category and severity for the 13 detection records are one pair, `Trojan` / `Severe`. That is
all this ADR records of them: what was detected and where is not read, and a category is Defender's label,
not a finding about the file or about the person. 1116 is level 3 here and level is not in any `match`
below, so that changes nothing.

**Reaching the logs.** The folder holds 414 `.evtx` files, 333 897 728 bytes. In the collector's order
(ADR 0024: `Security`, `System`, `Application`, then the rest by lower-cased name) the CodeIntegrity log is
66th with 80 093 184 bytes before it, and the Defender log is **375th with 305 491 968 bytes — 91 % of the
folder — before it**. So the Defender rule gets an answer only on a scan that reads nearly the whole folder
inside the 30-second `PARSE_BUDGET`. What is known about that:

- ADR 0042 records one elevated scan on this PC, on 2026-09-13, in which `event-log-not-at-configured-path`
  was `not_found`. Since a log the budget did not reach gaps every `evtx` field, that answer means **that scan
  read every log inside the budget**. Its duration was not recorded, and the folder has grown since.
- The runners read their whole folder inside the budget with a debug build, but hold about 210 logs, not 414.
- The Event Log service questions of ADR 0042 have their own 5-second `CONFIG_BUDGET` and are not charged to
  the parse budget; they feed only `configured_path`, `at_configured_path` and `max_size_bytes`, which no rule
  here reads.

**So, from these two facts alone, the Defender channel is reached on this PC as far as one scan shows, and
"reliably" is not established; the timed scan below adds a second, and its limits.** What protects the rule is the failure mode, not the order: if the budget runs out anywhere,
every `evtx` rule — this one included — is `unmeasured / budget_spent`, which no rule may declare and SS mode
lists (ADR 0032). It can make the row disappear into a listed "not measured"; it cannot make it read
`not_found` over logs that were never read. Moving the Defender log forward would buy an answer only in the
scans where the budget runs out, and would do it by leaving the other logs' rules unmeasured anyway; it is
not done. How long `evtx` takes on this PC is owner decision 5, measured below.

**The timed scan (owner decision 5), 2026-09-30**, same PC. The official 0.4.0 CLI
(`aeterna-rongroi-cli-0.4.0-windows-x64.exe`), checked against the release's `SHA256SUMS` and with
`gh attestation verify` exiting 0; `evtx`, its parser and the Windows host code are unchanged between the
`v2026.09.21-0.4.0` tag and `dev` (`git diff` over those paths is empty). One elevated `scan --json`,
standard tier, Self mode.

| | |
|---|---|
| `.evtx` files in the folder | 414, 318 MiB |
| folder account | `logs` 414 · `examined` 414 · `refused` 0 · `budget_exhausted` false · `budget_seconds` 30 |
| whole scan, wall clock, every collector | 20.9 s |

**So on this PC the Defender log, 375th of 414, was read inside the 30-second budget**, and so was every
other log. `evtx`'s own time was not taken apart from the scan's, so 20.9 s is an upper bound on it. The read
was **not cold**: the probe had read both channels earlier the same day, and the files were likely still in
the file cache, so a first scan after a restart may take longer. A PC with a slower disk or a larger folder
may still spend the budget. When it does, every `evtx` rule is a listed `unmeasured / budget_spent`, never a
quiet `not_found` (above), so no ADR on `PARSE_BUDGET` is needed now.

## Decision

### 1. Code Integrity 3033 and 3077: a timeline selector, not a rule

A 3033 was on one of two runners that nobody had used, and 476 on 15 days were on the PC, nine in ten of
them one installed program refusing another's DLL; the PC's 17 3077s were all drivers refused by a Microsoft
driver policy, with the blocklist and memory integrity on. A rule
on either would be `found` on ordinary machines, and it would put in front of an SS reviewer a row reading
"Windows blocked an image" with no way to say which image, blocked by which policy, for which process.
That is the shape of an accusation with the evidence left out.

What a reviewer can use is **when**: whether the last block sits beside the time FiveM last ran, or weeks
away from it. So this is one **timeline selector** (ADR 0051), `evtx/timeline/code-integrity-blocked-image`:

```yaml
role: timeline
collector: evtx
strength: context
match:
  provider: Microsoft-Windows-CodeIntegrity
  channel: Microsoft-Windows-CodeIntegrity/Operational
  event_id: [3033, 3077]
```

It makes no evidence and no count; it puts each group's `first_seen` and `last_seen` on the timeline in both
modes, with its text. Two ids on one channel are not the cross product ADR 0031 warns about: provider and
channel are single values.

Its `falsepositives`, in the order a reader should meet them:

- Microsoft's vulnerable driver blocklist, on by default on Windows 11, refusing an old driver that
  hardware utilities, RGB and fan control, overclocking tools and older anti-cheat software install
- Memory integrity, Smart App Control or S mode refusing a driver or program that does not meet their
  requirements
- A program that asks Windows to load only Microsoft-signed code into itself (Code Integrity Guard)
  refusing a DLL that another program tries to place in it: overlays, screen recorders, input tools,
  antivirus and accessibility software. Which programs on a PC do this is not measured
- A signature that was revoked or has expired on a file the PC still has
- An App Control policy an employer, a school or a PC maker installed

3004, 3089 and the policy-activation events are not selected: 3089 repeats a block that 3033 or 3077 already
dates, and the others are Windows starting up.

### 2. Defender 1116 and 1117: a timeline selector, not a rule

Neither runner had one; the PC had 9 and 4, all within one minute of one day. What Defender detected is in the payload. A browser toolbar, a
game trainer, a key generator and a file a download manager fetched are all "malware or other potentially
unwanted software" to Defender, and a false positive is recorded in the same words. A row saying "Defender
detected something" names none of them.

`evtx/timeline/defender-detection`, the same shape as section 1:

```yaml
match:
  provider: Microsoft-Windows-Windows Defender
  channel: Microsoft-Windows-Windows Defender/Operational
  event_id: [1116, 1117]
```

`falsepositives`: potentially unwanted software bundled with free programs; game trainers, mod tools, key
generators and cracked software, which antivirus products flag as unwanted software or hacking tools; a false positive on a new or unsigned
program; a file that was downloaded and never run; a detection in a file Defender removed at once.

### 3. Defender 5001: one rule, `context`

`evtx/defender/defender-real-time-protection-turned-off`:

```yaml
status: experimental
collector: evtx
strength: context
match:
  provider: Microsoft-Windows-Windows Defender
  channel: Microsoft-Windows-Windows Defender/Operational
  event_id: 5001
unmeasured_when: [not_windows, not_admin]
```

Title: "Microsoft Defender recorded that its real-time protection was switched off". The row carries the
count and the first and last time, and those times reach the timeline because the rule's evidence is
listed (ADR 0051 §4).

**Why a rule here and not in sections 1 and 2.** A 5001 says one thing and says it without the payload: at
this time, the part of Defender that scans files as they are opened stopped. It is the one of the five
events whose meaning does not depend on what the payload would have named. It was 0 on the PC. It was 1 on
each runner, and that one is the reason its `falsepositives` lead with the maker of the machine.

**Why `context` and not `posture`.** Whether real-time protection is on **now** is posture, and this rule
does not answer it — an event log records a change, not a state. And `view::ss_lists` lists a `posture`
rule's `not_found`: here that would be a row reading "we looked and Defender was never switched off", on a
log that rotates, that another antivirus may leave silent, and that is absent when Defender is. That is the
reasoning ADR 0031 gave for keeping the log-clearing rules out of `posture`, and it applies unchanged. Not
`tamper` either: nothing recorded was removed or altered.

**`falsepositives`**, in this order:

- The PC's maker, a shop or a Windows image turning real-time protection off before the PC was handed over
  — measured on both runner images
- The owner switching it off for a while to install or run something Defender flagged, often a game mod,
  a trainer or a tool shared on a forum, which is common advice for exactly those programs
- Installing another antivirus product; whether Defender records a 5001 when it steps aside is not
  established, so this entry is written as a possibility
- A Defender platform update, or a management tool or group policy of an employer or school
- Troubleshooting a slow PC or a game that stutters, which forum advice often starts by disabling real-time
  scanning

**`retention`:** only switches still in the Defender log as it stands; it holds up to 16 MiB by default and
overwrites its oldest records, and a cleared log holds none. If the Defender log is not there at all —
Defender removed from the image, or the file deleted — this row says `not_found` too, because `evtx` does
not know which logs a PC should have. `os_image`'s `service_windefend` and `install_marker`'s Defender
platform folder (ADR 0056, ADR 0057) are what answer that.

**`unmeasured_when: [not_windows, not_admin]`**, as every `evtx` rule since ADR 0032: `access_denied` is left
out because an elevated scan read every log on every machine measured, and `source_absent` is left out
because every Windows has an Event Log folder.

### 4. No new collector, field or reason

The rules and selectors read fields `evtx` already declares. The engine, the rule format, the report schema
and `Collector::fields` do not change.

### 5. Confrontation: three `rules/unconfronted.csv` rows

The one vendored Event Log sample is a LanguagePackSetup log. Its groups differ from each rule above in
provider, channel and event id — three conditions, not one — so no baseline confronts them, exactly as for
the log-clearing rules (ADR 0031, ADR 0033). Each gets a row whose `resolved_when` names a baseline holding a
CodeIntegrity or Defender log from a machine this project may publish, with both scans that
`fixtures/evtx/PROVENANCE.md` requires. No log is invented for a baseline.

## Alternatives weighed

| Alternative | Why not |
|---|---|
| A `context` rule on 3033 or 3077 with `count\|gte: N` | A threshold is a decision about how many blocks are too many; the PC had 200 and a runner nobody used had 4 |
| A rule on 3077 alone, since it is "the main block event for enforced policies" | On Windows 11 the enforced policy is, by default, Microsoft's driver blocklist; which policy it was is in the payload |
| A `context` rule on 1116/1117 | It would be `found` on the one ordinary PC measured, and it cannot name what was detected; the timeline carries the times without making a row of them |
| `posture` on 5001 | Lists a near-meaningless `not_found` in SS mode (section 3) |
| Reading the payload's policy name, file name or threat name | A new ADR on ADR 0018: the payload is where the personal data of this artifact is, and a threat name is a statement about a file on the player's PC |
| Moving the two logs to the front of the collector's order | Does not change any rule's answer, because an unread log gaps every field (section "Reaching the logs") |
| Adding 5010 or 5012 (scanning disabled) beside 5001 | Neither was measured on any machine here. A later change can add them with a measurement |

## What is unverified

- **Whether a 5001 is written when another antivirus is installed.** Not documented, not measured; the PC
  has Defender alone, so the probe could not answer it. It
  decides whether the third `falsepositives` entry is a real cause or a possibility.
- **Which policy wrote the PC's 3077s** — answered on 2026-09-30: `Microsoft Windows Driver Policy`, all
  drivers. That this name is the vulnerable driver blocklist's is inferred, not documented.
- **Whether a PC with about 400 logs reaches the Defender log inside the 30-second budget, every time.** Two
  scans on the PC did — one inferred from ADR 0042's `not_found`, one timed at 20.9 s for the whole scan on a
  warm file cache. A cold read, a slower disk or a larger folder is not measured.
- **How long the Defender log reaches back on a player's PC.** Two months in a fifth of its 16 MiB on the
  PC; a PC with more Defender activity keeps less.
- **Whether the timeline selectors make the SS timeline unreadable** on a PC with hundreds of blocks. A
  selector adds two times per group, not one per event, so the PC's 476 3033s and 17 3077s would add four entries; that is
  arithmetic from the collector's grouping, not a rendered view.
- **Which programs on a player's PC use Code Integrity Guard**, and so how many 3033 events an overlay or
  recorder produces there. Microsoft documents the mechanism, not a list.
- **Whether Server 2022's four 3033 events are what a Windows 11 PC's are.** A server image is not a
  gaming PC. It shows only that a 3033 needs neither a player nor a cheat.

## Owner decisions (2026-09-30)

1. Code Integrity 3033 and 3077 get one timeline selector and no evidence rule (section 1).
2. Defender 1116 and 1117 get one timeline selector and no evidence rule (section 2).
3. Defender 5001 gets one rule, `context` and `experimental` (section 3).
4. No baseline is added in this change: the rule and the two selectors each get a `rules/unconfronted.csv`
   row (section 5). Vendoring a runner's CodeIntegrity and Defender logs as a baseline, if it is ever done,
   is a separate pull request that runs `fixtures/evtx/PROVENANCE.md`'s two scans first.
5. **Before the change that adds the rule and the selectors merges**, one elevated scan of a release build on
   the Windows 11 PC (build 26220) records how long `evtx` takes, with the folder account's `examined`,
   `refused` and `budget_exhausted`. If the budget is near its end, the answer is an ADR on `PARSE_BUDGET`,
   not a reordering of the logs. **Met on 2026-09-30** ("The timed scan" under the PC measurement): 414 of
   414 logs examined, `budget_exhausted` false, 20.9 s for the whole scan on a warm file cache. No
   `PARSE_BUDGET` ADR is needed now; a colder or larger PC may still spend the budget, and shows it as a
   listed `unmeasured`.

The points under "What is unverified" stay open; the change that adds the rules says which it measured.

## Consequences

- `rules/evtx/timeline/code-integrity-blocked-image/`, `rules/evtx/timeline/defender-detection/` and
  `rules/evtx/defender/defender-real-time-protection-turned-off/`, each with positive and negative fixtures
  — the negatives built from the collisions that matter: the same id from another provider, and the same
  provider with a neighbouring id (5000 beside 5001, 3089 beside 3033) — Thai text in `rules/i18n/th.yaml`,
  and `docs/rules-reference*.md` regenerated.
- **Two timeline selectors widen what SS mode shows.** The consent question in
  `crates/rongroi-cli/src/output.rs` (both languages), the desktop's `consent.shows` and `PRIVACY.md` name
  them in the same change, as `rules/AGENTS.md` requires of a selector.
- Three `rules/unconfronted.csv` rows.
- The `evtx` collector's module header names the new rules.
- The Windows CI job's scan of its runner will show the 5001 rule `found`, from the image. Nothing there
  asserts it is not.
- No change to Rust code, the rule format or either schema version.

## The probe for the PC

A read-only PowerShell script, run elevated once, prints for each of the two channels: whether it is
enabled, its mode, its maximum and current size, its record count and whether it is full; the oldest and
newest record; provider and channel as recorded; per event id and level a count with the first and last
time, and on how many distinct days each id of interest appeared. For 3033 and 3077 it groups events by the
blocked file's extension (`.sys`, `.dll`, `.exe`, other), where that file and the requesting process live
(a shape such as `system32`, `program files`, `user appdata` — never a name), and, for 3077, the policy
name; for 1116 and 1117, by Defender's category and severity names. It then prints Defender's current state,
how many antivirus products Security Center lists and how many of them are not Defender, the vulnerable
driver blocklist, Smart App Control and memory integrity settings, and where the two logs fall in the
collector's order with how many bytes come before them. It prints no file name, process name, user name,
threat name or machine name, and writes nothing. The script is kept outside the repository.
