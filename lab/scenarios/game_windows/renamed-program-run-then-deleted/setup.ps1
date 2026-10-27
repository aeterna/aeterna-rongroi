# SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
# SPDX-License-Identifier: GPL-3.0-or-later
# Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

$ErrorActionPreference = 'Stop'

# This is what a renamed program run shortly before playing leaves behind: a file in the user's profile, run
# once and then deleted. The program is this repository's own build with bytes added at the end, so the engine
# does not set it aside as the running program's own trace (ADR 0010), and it does nothing on its own. The trace
# is the recorded run, not what the program does.
$folder = Join-Path $env:LOCALAPPDATA 'rongroi-lab'
New-Item -Path $folder -ItemType Directory -Force | Out-Null
$helper = Join-Path $folder 'helper.exe'
Copy-Item -Path (Join-Path $PSScriptRoot 'rongroi.exe') -Destination $helper -Force
[System.IO.File]::AppendAllText($helper, 'rongroi lab scenario copy')
# A normal window and -PassThru: in one probe BAM did not record a program started with a hidden window.
# -Wait keeps this step ordered; the program exits after printing its help.
Start-Process -FilePath $helper -ArgumentList '--help' -Wait -PassThru -WindowStyle Normal | Out-Null

# Twenty seconds later, so the recorded run falls inside the 30 minutes before the session, not at its start.
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

# After the session has started, the program is gone, as a loader that deletes itself would be. Only the inert
# file this scenario made is removed; nothing Windows wrote is touched.
Start-Sleep -Seconds 20
Remove-Item -Path $helper -Force
