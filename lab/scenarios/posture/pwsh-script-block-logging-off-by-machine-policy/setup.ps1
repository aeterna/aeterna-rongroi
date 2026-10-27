# SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
# SPDX-License-Identifier: GPL-3.0-or-later
# Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

$ErrorActionPreference = 'Stop'

# PowerShell 7 need not be installed for this trace: the policy is a registry value either way, and the
# collector reads the registry, not the PowerShell binary. PowerShell 7 counts only a REG_DWORD here.
$key = 'HKLM:\SOFTWARE\Policies\Microsoft\PowerShellCore\ScriptBlockLogging'
New-Item -Path $key -Force | Out-Null
New-ItemProperty -Path $key -Name 'EnableScriptBlockLogging' -PropertyType DWord -Value 0 -Force | Out-Null
Get-ItemProperty -Path $key -Name 'EnableScriptBlockLogging'
