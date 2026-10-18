# SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
# SPDX-License-Identifier: GPL-3.0-or-later
# Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

$ErrorActionPreference = 'Stop'

# This is what a program writes when it is set to start at sign-in from the user's profile: an unsigned program
# in AppData, named by a Run value under HKCU. Here the program is this project's own unsigned build, which does
# nothing on its own; the trace is the entry and the file, not anything the program does.
$folder = Join-Path $env:LOCALAPPDATA 'rongroi-lab'
New-Item -Path $folder -ItemType Directory -Force | Out-Null
$target = Join-Path $folder 'lab-tool.exe'
# The engine sets aside any observation that carries the running program's own digest as the tool's own trace
# (docs/adr/0010-process-source-and-own-traces.md), so an unchanged copy would never reach the rule. Bytes after
# the end of a program file leave it an unsigned program that still does nothing on its own.
Copy-Item -Path (Join-Path $PSScriptRoot 'rongroi.exe') -Destination $target -Force
[System.IO.File]::AppendAllText($target, 'rongroi lab scenario copy')

$key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
New-ItemProperty -Path $key -Name 'rongroi-lab' -PropertyType String -Value "`"$target`"" -Force | Out-Null
Get-ItemProperty -Path $key -Name 'rongroi-lab'
