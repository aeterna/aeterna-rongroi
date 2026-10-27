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
before the session, so T1 is true. The scenario also asks for I1 to read `not_known:no_path`: BAM names the
program as `\Device\HarddiskVolumeN\…`, a form the collector withholds, so the view has no path at which to
check the file (ADR 0078, "P7 decisions" item 3). The scenario names no rule that must read `found`.

## What the scenario does not show

- That the file is gone. The scenario deletes it after the session starts, but BAM's path is not drive-rooted,
  so I1 cannot be shown and reads `not_known:no_path` instead. I5, the change journal's record of a rename or
  deletion, is not computed by this build (ADR 0078, "As built: P6a" item 4).
- Which drive or folder BAM's `\Device\HarddiskVolumeN\…` names. Mapping a volume to its drive letter is the
  drive map that follows ADR 0082, not part of this scenario.
- The windows during the session, after it, and before the scan. A session whose game is still running has no
  end, so those windows are "not known" (ADR 0078 section 3).
- What the program is, who ran it, or whether it did anything. The bytes say only that it is this repository's
  build, and the recorded run says only that Windows saw it start.

See [ADR 0076](../../../../docs/adr/0076-lab-replay.md) and
[ADR 0078](../../../../docs/adr/0078-programs-recorded-near-a-game-session.md).
