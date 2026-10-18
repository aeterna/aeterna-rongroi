# Application event log cleared

## What the trace stands for

Someone cleared the Application event log: Event Viewer's "Clear Log", `wevtutil cl Application`, or a PC
"optimiser" script that clears logs in one click. Windows then writes its own record of the clearing to the
System log as event 104, from `Microsoft-Windows-Eventlog`. That record is the trace. It does not say who
cleared the log or why, and it does not say what the Application log held before.

## What the scenario shows

The evtx collector reads the System log's event 104 from `Microsoft-Windows-Eventlog`, and
`evtx/log-clearing/event-log-file-cleared` reads `found`. The Security log is not cleared, so no 1102 is
written there, and `evtx/log-clearing/security-audit-log-cleared` stays `not_found`. The machine restarts once between the
clearing and the scan (restart: true in expect.yaml).

## What the scenario does not show

- Who cleared the Application log, why, or whether they knew it would be recorded.
- Which log was cleared. The 104 names it inside its record, and the rule reads only the provider, channel and
  event id, so the rule cannot say which of the PC's logs this was.
- Whether a clearing of the Security log also writes a 104. The Security neighbour here is `not_found` only
  because this scenario does not touch that log.
- Whether the Application log's earlier records survive. `wevtutil cl` removes them, as a clearing does; the
  scenario does not test what they held.

See [ADR 0076](../../../../docs/adr/0076-lab-replay.md) and
[ADR 0031](../../../../docs/adr/0031-the-log-clearing-rules.md).
