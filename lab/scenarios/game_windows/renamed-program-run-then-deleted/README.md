<!-- SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md. -->

# Renamed program run before a session, then deleted

## What the trace stands for

A program named `helper.exe` in `%LOCALAPPDATA%\rongroi-lab`, run and closed shortly before a game session and
deleted after it starts. That is the shape a loader or a clean-up tool leaves around a session: an ordinary
user folder, a name that says nothing about the program, a recorded run just before play, and no file afterwards
(ADR 0078 sections 4 and 5). The file is this repository's own unsigned build with a few bytes added at the end,
so it is not the running program's own trace
([ADR 0010](../../../../docs/adr/0010-process-source-and-own-traces.md)) and it does nothing on its own. What the
trace shows is the recorded run, not what the program does.

## What the scenario shows

BAM records that `helper.exe` ran. The session is a `FiveM.exe` that is still running when the scan reads, so it
has a start and the view is computed (ADR 0076, "Amendment (2026-10-27)"). The candidate is in the 30 minutes
before the session, so T1 is true. The scan is a full scan (`full: true`), so `recorded_files` reads the file at
the candidate's path and the change journal once. Since M1, ADR 0087's drive map turns the
`\Device\HarddiskVolumeN\…` path BAM records into a drive-rooted `C:\…` path, so the view has a path at which to
check the file: the scenario deleted it, so I1 is true. I5 is true for the same path, because the change journal
holds its deletion near the session (ADR 0086, section 5). The scenario names no rule that must read `found`.

## What the scenario does not show

- That the file is gone for a reason other than this scenario. The scenario deletes the file it made after the
  session starts, so I1 is true and I5 records the deletion; no other process removes or changes it.
- Which drive or folder BAM's `\Device\HarddiskVolumeN\…` named when Windows wrote the record. ADR 0087's drive
  map gives the letter that volume has at scan time, and `path_from_device` says the report's path came from a
  device path; a volume removed or reused since is outside the scenario (ADR 0087 section 3).
- The windows during the session, after it, and before the scan. A session whose game is still running has no
  end, so those windows are "not known" (ADR 0078 section 3).
- What the program is, who ran it, or whether it did anything. The bytes say only that it is this repository's
  build, and the recorded run says only that Windows saw it start.

See [ADR 0076](../../../../docs/adr/0076-lab-replay.md),
[ADR 0078](../../../../docs/adr/0078-programs-recorded-near-a-game-session.md),
[ADR 0086](../../../../docs/adr/0086-change-journal-for-a-candidates-file.md) and
[ADR 0087](../../../../docs/adr/0087-drive-map-for-device-paths.md).
