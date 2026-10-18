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
Copy-Item -Path (Join-Path $PSScriptRoot 'rongroi.exe') -Destination $target -Force

$key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
New-ItemProperty -Path $key -Name 'rongroi-lab' -PropertyType String -Value "`"$target`"" -Force | Out-Null
Get-ItemProperty -Path $key -Name 'rongroi-lab'
