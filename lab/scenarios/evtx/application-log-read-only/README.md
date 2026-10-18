# Application log file set read-only

## What the trace stands for

The Application event log file, `%SystemRoot%\System32\winevt\Logs\Application.evtx`, with the read-only
attribute set on it. That is the change `attrib +R` or the file's Properties checkbox makes, and the scenario
makes it the same way an administrator would, with `IsReadOnly`. The file stays where the Event Log service
keeps it. Nothing is removed, emptied or renamed.

## What the scenario shows

The evtx collector reads the attribute of each log file in the Event Log folder, and
`evtx/log-file/event-log-file-read-only` reads `found` for the one file that carries it. The neighbour
`evtx/log-file/event-log-not-at-configured-path` stays `not_found`: the Application channel is still written to
this same file, so the log is where the service is configured to keep it.

## What the scenario does not show

- Who set the attribute, when, or why. The rule says the same of any log file that carries it.
- Whether Windows honours the attribute, or what the Event Log service does to a file that carries it. The
  collector reads the bit; this scenario does not test the service's behaviour, and ADR 0037 records that
  this was not tested on the one machine measured.
- The ordinary causes the rule lists: a read-only attribute applied through a folder's Properties, or a log
  copied or restored by software that keeps file attributes. The scenario does not tell those apart from this one.
- Whether any other log file, or any Windows build, carries the attribute. Only this file is changed here.

See [ADR 0076](../../../../docs/adr/0076-lab-replay.md) and
[ADR 0037](../../../../docs/adr/0037-prefetch-configuration-and-the-read-only-attribute.md).
