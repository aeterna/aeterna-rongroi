# SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
# SPDX-License-Identifier: GPL-3.0-or-later
# Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

$ErrorActionPreference = 'Stop'

# This is what an administrator changing the machine's clock by hand looks like: the time moves forward and
# back near a session. Windows records the change itself in Security event 4616 and Kernel-General event 1.
# The scenario never back-dates any record; it only moves the clock the way an administrator can.
Set-Date -Date (Get-Date).AddMinutes(5)
Start-Sleep -Seconds 5
Set-Date -Date (Get-Date).AddMinutes(-5)

# Twenty seconds later, so the change falls inside the span the view compares.
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
