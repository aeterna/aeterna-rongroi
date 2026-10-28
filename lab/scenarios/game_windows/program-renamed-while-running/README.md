<!-- SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md. -->

# Program renamed while running, before a session

## What the trace stands for

A program in `%USERPROFILE%\Downloads` that is renamed while it is still running, and keeps running into a game
session. Windows lets a running program's file be renamed in the same folder, so the name it ran under is no
longer the name on disk. That is one way a program can hide the name it ran under: the file the user sees holds a new
name, while which name Windows' records keep is the replay's to show ("What is unverified"). The change journal records the rename as an
old-name record and a new-name record (ADR 0086, section 2). The file is Windows' own `ping.exe`, copied, so it
is inert: it pings the loopback address and the machine has no network.

## What the scenario shows

The program `renamer.exe` is started in Downloads, renamed to `renamed.exe` five seconds later while it runs, and
keeps running when the session starts, so the process list gives it a drive-rooted path. The candidate is in the
30 minutes before the session, so T1 is true. The scan is a full scan (`full: true`), so `recorded_files` reads
the change journal once. The journal holds the rename's records for the file's folder, and I5 is true when one of
them falls in a window of the latest session: each record is matched by its folder and name, or by the file's own
number, which is the same whichever name it has. The journal's records are compared on the PC and never kept; the
report shows only that a rename was recorded and when (ADR 0086, sections 2 and 3). The scenario names no rule
that must read `found`.

## What the scenario does not show

- What the program does or who renamed it. The file is a copy of `ping.exe`, and the rename is made by the
  scenario, not by a loader.
- That the file is gone, or where it is now. The file still exists under its new name, so I1 is not asserted.
- That a rename is what a loader does, or that a rename is evidence of anything. A rename is also an update, a
  Recycle Bin move or an antivirus action (ADR 0086, "What is unverified").
- The windows during the session, after it, and before the scan. A session whose game is still running has no
  end, so those windows are "not known" (ADR 0078 section 3).
- Anything about Downloads other than this one file. The collector reads only the paths a record points at, and
  this scenario makes one.

## What is unverified

- Why the process list keeps the old name. The first replay (2026-10-28) showed the candidate named
  `renamer.exe` with the path `…\Downloads\renamed.exe` (ADR 0086, "As built: J5"); that this holds on other
  builds of Windows is not measured.
- Whether the journal holds one old-name record and one new-name record for the rename, or more. J4 read the
  journal of one other PC, not the lab machine, and no rename was made there (ADR 0086, "Measured: J4").

See [ADR 0076](../../../../docs/adr/0076-lab-replay.md),
[ADR 0078](../../../../docs/adr/0078-programs-recorded-near-a-game-session.md) and
[ADR 0086](../../../../docs/adr/0086-change-journal-for-a-candidates-file.md).
