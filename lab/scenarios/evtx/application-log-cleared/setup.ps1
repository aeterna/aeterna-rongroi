# SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
# SPDX-License-Identifier: GPL-3.0-or-later
# Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

$ErrorActionPreference = 'Stop'

# This is what Event Viewer's "Clear Log" or a PC "optimiser" script does to the Application log.
# Clearing a log writes Windows' own record of the clearing (System, event 104); that record is the trace.
wevtutil cl Application
Get-WinEvent -FilterHashtable @{LogName='System'; Id=104} -MaxEvents 1 | Format-List TimeCreated,ProviderName,Id
