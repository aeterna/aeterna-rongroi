# SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
# SPDX-License-Identifier: GPL-3.0-or-later
# Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

$ErrorActionPreference = 'Stop'

# This is what an administrator's Group Policy "Turn on PowerShell Script Block Logging = Disabled" writes.
$key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
New-Item -Path $key -Force | Out-Null
New-ItemProperty -Path $key -Name 'EnableScriptBlockLogging' -PropertyType DWord -Value 0 -Force | Out-Null
Get-ItemProperty -Path $key -Name 'EnableScriptBlockLogging'
