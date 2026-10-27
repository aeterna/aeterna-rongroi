<!-- SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md. -->

# Clock changed by hand before a session

## What the trace stands for

An administrator changing the machine's clock by hand: five minutes forward, five seconds later five minutes
back, and a game session twenty seconds after that. Windows records the change itself, in Security event 4616
(the audit event for a system time change) and in the System log's Kernel-General event 1. That record is the
trace. The scenario never back-dates any record; it only moves the clock the way an administrator can.

## What the scenario shows

On the lab machine the audit policy logs "Security State Change" (measured 2026-10-27), so the change leaves a
Security 4616 record beside the Kernel-General record. The session is a `FiveM.exe` still running when the scan
reads (ADR 0076, "Amendment (2026-10-27)"), and the change falls inside the span the view compares. The view's
clock line therefore names at least one change, and `clock_changed: true` checks that. The scenario names no
rule that must read `found`.

## What the scenario does not show

- Who changed the clock, or why. An administrator, a time service, a dual-boot machine or a virtual machine's
  own clock handling can all move it, and the record says only that it moved.
- That any record was back-dated or altered. The scenario never does that; it shows only that a clock change
  near a session is recorded and reaches the view.
- The exact times on both sides of the change. The view prints what the event records hold.
- The windows during the session, after it, and before the scan. A session whose game is still running has no
  end, so those windows are "not known" (ADR 0078 section 3).
- Whether another PC's audit policy records the change. The Security 4616 record depends on the audit policy,
  and this measurement is the lab machine's.

See [ADR 0076](../../../../docs/adr/0076-lab-replay.md) and
[ADR 0078](../../../../docs/adr/0078-programs-recorded-near-a-game-session.md).
