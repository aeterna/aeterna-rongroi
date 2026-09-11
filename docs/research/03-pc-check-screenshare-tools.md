# 03 — PC-check and screenshare tools (2026-09-11)

## Summary

- Every commercial PC-check tool found is **closed-source, online and subscription-based**; the verdict goes
  to the staff member's dashboard, not the player's screen.
- **No mature, licensed, maintained open-source FiveM PC-check tool was found.**
- An offline tool whose output the player controls **cannot prove innocence**. It can present evidence.
- Many Windows artifacts age out within days, and several only show *presence*, not *execution*.

## Commercial tools

| Tool | Model | Checks (as described) | Notes |
|---|---|---|---|
| Echo | closed, online dashboard | processes, strings, uploaded executables (vendor claim) | its kernel driver had CVE-2023-38817, a local privilege escalation ([CVE](https://www.cvedetails.com/cve/CVE-2023-38817/), [research](https://github.com/kite03/echoac-poc/)); players raised data-retention concerns |
| Ocean (anticheat.ac) | closed, online | Prefetch, Amcache, ShimCache, BAM, event logs, PCA, execution from external devices (vendor claim, [docs](https://anticheat.ac/docs/detections/detection-systems)) | collects a desktop screenshot and identifiers; screenshots kept 21 days ([terms](https://anticheat.ac/tos)) |
| Detect.ac | closed, online | many methods, low false positives (vendor claim) | bans accounts that scan themselves ([reviews](https://www.trustpilot.com/review/detect.ac)) |
| Paladin, Avenge | closed | Minecraft-focused | criticised in 2021 for using remote-desktop software and scanning search history ([thread](https://hypixel.net/threads/opinion-avenge-3-0-avenge-ac-is-literally-a-joke.4568346/)) |

## Free forensic utilities staff use

System Informer / Process Hacker (live processes), LastActivityView
([NirSoft](https://www.nirsoft.net/utils/computer_activity_view.html)), Everything
([voidtools](https://www.voidtools.com/faq/)), JournalTrace
([GitHub](https://github.com/ponei/JournalTrace)), BAM and Prefetch parsers.

## Artifacts and what they prove

| Artifact | Proves | Retention | Cleanable | False-positive risk |
|---|---|---|---|---|
| Prefetch | a program **ran**; up to 8 run times on Win8+ ([Magnet](https://www.magnetforensics.com/blog/forensic-analysis-of-prefetch-files-in-windows/)) | up to 1,024 files; can be disabled | yes | low for execution, high if matched by name only |
| BAM/DAM | full path + last execution time per user ([IT-Connect](https://www.it-connect.tech/forensic-windows-part-5-analyzing-bam-and-dam/)) | entries older than 7 days removed at boot; not recorded for removable or network drives | registry | low–medium |
| Amcache | a file was **present**, with SHA-1 — **not** proof of execution ([Windows IR](http://windowsir.blogspot.com/2024/11/program-execution-shimcacheamcache-myth.html)) | long | possible | medium |
| ShimCache | **presence** only; written at shutdown | long | possible | **high** if read as execution |
| PCA (`PcaAppLaunchDic.txt`, Win11 22H2+) | Explorer launches, including from USB, with UTC time ([Sygnia](https://www.sygnia.co/blog/new-windows-11-pca-artifact/)) | not found | plain text file | low |
| USN journal | file create / delete / rename | circular; days to weeks ([artefacts.help](https://artefacts.help/windows_usnjrnl.html)) | yes | high (normal activity) |
| Event logs | logons, installs, crashes; clearing writes event 1102 (Security) or 104 (others) ([1102](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=1102)) | size-limited | clearing is itself logged | low |
| SRUM | per-app resource use, including deleted binaries | ~30 days apps, ~60 days network | locked database | medium |
| ShellBags | a folder was browsed | long | possible | medium |
| Recycle Bin `$I` files | original path, size, deletion time | until emptied | trivially | low |

## FiveM-specific artifacts

- `%localappdata%\FiveM\FiveM.app` holds `CitizenFX.ini` and logs.
- The `plugins` folder is where the FiveM manual says `.asi` files go; servers can disallow plugins
  ([manual](https://docs.fivem.net/docs/client-manual/)).
- **ReShade files (`dxgi.dll`, presets) in `plugins` are the officially documented location** — flagging them
  by name would be a false positive.
- `sv_pureLevel` enforces file hashes but does not stop memory cheats or external overlays.
- Not found: a public guide listing executor file names or loader traces for FiveM.

## How screenshares are defeated (categories only)

Community guides list concealment, timestamp manipulation, clearing Prefetch / registry / journal / event
logs, running from removable media or virtual machines, and capture-proof overlays. Cheats on a second PC
(DMA) leave nothing on the checked PC. The more robust signals are **gaps and contradictions**: cleared-log
events, execution traces whose files are gone, launches from removable media.

## Integrity of an offline tool

Commercial tools avoid trusting the player's screen by sending results to staff. Offline, the best available
measures are signed/attested releases ([GitHub docs](https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations/verifying-attestations-offline)),
reproducible or at least verifiable builds, and a "download fresh and compare the hash during the call" step.
None of them defeats a tampered operating system.

## Policy and norms

- Cfx forum, February 2025: players were told they are not obliged to comply with PC checks
  ([thread](https://forum.cfx.re/t/server-forcing-users-to-download-third-party-anti-cheat-software/5304909)).
- Cfx forum, July 2026: consensus that PC checks are not against the terms but are coercive and poor practice
  ([thread](https://forum.cfx.re/t/question-regarding-pc-checks-and-rockstar-cfx-re-terms/5416932)).
- Stratus Network (Minecraft) limits staff to game-related folders, allows the player to ask for reasons,
  and forbids recording ([policy](https://stratus.network/screensharing)).

## What this meant for aeterna-rongroi

- Report evidence, never "clean"; show each source's retention next to "not found".
- Label ShimCache / Amcache as presence; require agreement between artifacts before calling something executed.
- Put tamper and gap signals first.
- Allow legitimate FiveM add-ons (ReShade) by hash or signer, never by name.
- User-mode, read-only, no driver, no screenshots, no browser history.
- Consent screen that says refusing is allowed; redact user names; export only on click.
- Visible build provenance and hash verification, with honest limits.
