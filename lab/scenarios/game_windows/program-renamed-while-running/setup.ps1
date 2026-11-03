# SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
# SPDX-License-Identifier: GPL-3.0-or-later
# Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

$ErrorActionPreference = 'Stop'

# This is what a program leaves behind when its file is renamed while it runs: a program in Downloads whose file
# is renamed under it, so the name it ran under is not the name on disk any more. The file is Windows' own
# ping.exe, so it is inert; the trace is the rename the change journal records and the recorded run.
$downloads = Join-Path $env:USERPROFILE 'Downloads'
New-Item -Path $downloads -ItemType Directory -Force | Out-Null
$tool = Join-Path $downloads 'renamer.exe'
Copy-Item -Path (Join-Path $env:SystemRoot 'System32\PING.EXE') -Destination $tool -Force
# The program keeps running after it starts, so the process list gives its drive-rooted path while it runs.
# A normal window and -PassThru: in one probe BAM did not record a program started with a hidden window.
# No -Wait: the rename below happens while the program is running.
$null = Start-Process -FilePath $tool -ArgumentList '-n','900','127.0.0.1' -PassThru -WindowStyle Normal

# Five seconds later, so the program is running when its file is renamed.
Start-Sleep -Seconds 5
# NTFS allows a running program's file to be renamed in the same folder. The change journal then holds an
# old-name record and a new-name record for this file. Nothing is copied or deleted; only the name changes.
Rename-Item -Path $tool -NewName 'renamed.exe'

# Twenty seconds later, so the recorded start and the rename fall inside the 30 minutes before the session.
Start-Sleep -Seconds 20

# The session: Windows' own ping.exe copied under FiveM's folder and still running when the scan reads, as a
# player's game is during a screenshare (ADR 0076, "Amendment (2026-10-27)" §2). The lab machine's Prefetch
# writes no file for this name, so an ended session would have no start; the running process gives the start.
$sessionFolder = Join-Path $env:LOCALAPPDATA 'FiveM'
New-Item -Path $sessionFolder -ItemType Directory -Force | Out-Null
$game = Join-Path $sessionFolder 'FiveM.exe'
Copy-Item -Path (Join-Path $env:SystemRoot 'System32\PING.EXE') -Destination $game -Force
# No -Wait: the game is still running at the scan. A normal window, because a hidden window was not recorded by
# BAM in one probe.
$null = Start-Process -FilePath $game -ArgumentList '-n','900','127.0.0.1' -PassThru -WindowStyle Normal
