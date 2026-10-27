# SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
# SPDX-License-Identifier: GPL-3.0-or-later
# Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

$ErrorActionPreference = 'Stop'

# This is what a program downloaded from a website and run just before playing leaves behind: a file in
# Downloads, still running when the game starts, with the marker Windows writes when a browser saves it. The
# file is Windows' own ping.exe, so it is inert; the trace is the file, its stream and its recorded run.
$downloads = Join-Path $env:USERPROFILE 'Downloads'
New-Item -Path $downloads -ItemType Directory -Force | Out-Null
$tool = Join-Path $downloads 'tool.exe'
Copy-Item -Path (Join-Path $env:SystemRoot 'System32\PING.EXE') -Destination $tool -Force
# A browser writes a Zone.Identifier stream beside the file: the zone it came from and the address it came from.
# The address is a documentation domain that does not resolve, so nothing is downloaded and no network is used.
Set-Content -Path $tool -Stream 'Zone.Identifier' -Value "[ZoneTransfer]`r`nZoneId=3`r`nHostUrl=https://downloads.example.invalid/tool.exe"
# The downloaded program is still running when the game starts, so the process list gives its drive-rooted path.
# A normal window and -PassThru: in one probe BAM did not record a program started with a hidden window.
$null = Start-Process -FilePath $tool -ArgumentList '-n','900','127.0.0.1' -PassThru -WindowStyle Normal

# Twenty seconds later, so the recorded start falls inside the 30 minutes before the session.
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
