# ADR 0042 — What the Event Log service says a channel writes to

- Status: proposed
- Date: 2026-09-13

## Context

ADR 0028 left two questions about an event log file open because the `.evtx` bytes cannot answer
them:

> **`maxSize` is not read, so the single most informative corroborator in the research is absent.**

and, from ADR 0024 on, that a log file whose records name a channel other than the one it is named
after "is a file that was put there" — a shape `fixtures/hosts/PROVENANCE.md` forbids a baseline to
show, and one no field could express, because nothing said what file a channel *should* be in.

The brief for this work asked for two signals at the level of a log file: a file whose name differs
from the file the channel is configured to write, and a channel whose configured maximum size is
unusually small. Both need the channel's configuration, which is not in the file. Where it is, and
what "configured" means, had to be measured first, because the obvious answer — read it from the
registry — turned out to be the wrong one.

## What was measured, and where

On 2026-09-13, on one Windows 11 machine (build 26220), read-only throughout.

**The registry does not hold one answer.** Three places look like a channel's configuration:

| Key | What was there |
|---|---|
| `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\<log>` | Documented for the classic logs ([Eventlog Key](https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key)). `File` present on 4 logs (`Application`, `HardwareEvents`, `Security`, `System`) and **absent** on the rest; `MaxSize` on 10. The doc: `File` "is optional. If the value is not specified, it defaults to %SystemRoot%\system32\winevt\logs\ followed by a file name that is based on the event log registry key name." |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\<channel>` | 1 232 keys. **No key held a `File` value.** `MaxSize` and `MaxSizeUpper`, both `REG_DWORD`, on 84. No key at all for `Application`, `Security` or `System`. No Microsoft page found documents this key |
| `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\<log>` | **Absent.** The policy CSP documents the key names for `Application`, `Security`, `Setup` and `System`, and gives a registry *value* name for `Retention` and `AutoBackupLogFiles` but **none** for the file-path and maximum-size policies ([ADMX_EventLog](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-eventlog)); the machine has no `PolicyDefinitions\EventLog.admx` to read them from |

**And the registry's number is not the size Windows uses.** `Get-WinEvent -ListLog *` reports each
channel's effective `MaximumSizeInBytes`. Against it:

- 14 of the 84 `WINEVT\Channels` keys carrying `MaxSize` disagreed. Thirteen held a value below
  1 052 672 (1 048 576, 1 000 000, 655 360, 524 288 or 262 144) and were 1 052 672 in effect; one held
  262 144 and was 16 777 216 in effect.
- 4 of the 10 classic keys carrying `MaxSize` disagreed, all four held by applications' own logs, at
  131 072 or 524 288 in the registry and 1 052 672 in effect.

**The effective sizes.** Of 1 243 channels, 1 166 were at 1 052 672 bytes; the rest ranged from
4 MiB to about 1 GiB. `Application`, `Security` and `System` were each 20 971 520.

**The effective file names.** For all 1 243 channels, the effective path was
`%SystemRoot%\System32\Winevt\Logs\` followed by the channel's name with `/` written `%4` — no
exception, no path outside that folder. 411 of those files existed. Two `.evtx` files in the folder
belonged to no channel, `Parameters.evtx` and `State.evtx`, which are also the names of two subkeys of
`Services\EventLog` that are not logs.

**Under a limited token**, `Services\EventLog\Security` could not be opened at all, while
.NET's `EventLogConfiguration` — which reports the same two properties the calls chosen below read;
whether it makes those calls was not read — answered for `Security`,
`System`, `Application` and two modern channels, and answered "The specified channel could not be
found" for one that does not exist.

Then this pull request's CLI, cross-built, was run there **elevated**: 413 log accounts; 148 of them
held records of exactly one channel and were compared; **148 `at_configured_path: true`, 0 `false`**;
no log with records named a channel the service did not know; 265 held no records and were not
compared. The rule below was `not_found`. Under a limited token every log was refused, so none was
compared, and the rule was `unmeasured / not_admin`.

## Decision

### 1. A source of its own: `EventLogConfigSource`

```rust
pub struct ChannelConfig { pub log_file_path: String, pub max_size_bytes: u64 }

pub trait EventLogConfigSource {
    fn channel_config(&self, channel: &str) -> Result<Option<ChannelConfig>, SourceError>;
}
```

`LiveHost` answers with `EvtOpenChannelConfig` and `EvtGetChannelConfigProperty` for
`EvtChannelLoggingConfigLogFilePath` and `EvtChannelLoggingConfigMaxSize`
([EVT_CHANNEL_CONFIG_PROPERTY_ID](https://learn.microsoft.com/en-us/windows/win32/api/winevt/ne-winevt-evt_channel_config_property_id):
"the path to the file that backs the channel"; "the **maxSize** logging attribute of the channel"),
and closes the handle with `EvtClose` on every path. It is the service's own statement of the
channel's configuration — the same properties `wevtutil gl` and `Get-WinEvent -ListLog` present
(which calls those tools make was not read) — and so the thing the three registry locations above
could only approximate.

**Why a new trait and not the registry.** Every other host source is split by what it touches (ADR
0019, 0022). This one touches the Event Log service, not a key or a file. And the registry reading
would have been wrong in the direction that matters: a registry `MaxSize` of 131 072 on a log Windows
sizes at 1 052 672 would have been reported as a log capped at an eighth of its real size.

**Read-only, and documented as such.** `EvtOpenChannelConfig` "gets a handle that you use to read or
modify a channel's configuration property"; modifying needs `EvtSetChannelConfigProperty` and then
`EvtSaveChannelConfig`
([EvtOpenChannelConfig](https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtopenchannelconfig)).
Neither is called anywhere in this program. The session is `NULL` — "to access a channel on the local
computer" — so nothing leaves the machine.

**Answers.** `ERROR_EVT_CHANNEL_NOT_FOUND` (15007) is `Ok(None)`: a log file can outlive the software
that registered its channel, and "the service has no such channel" is an answer. `ERROR_ACCESS_DENIED`
is `AccessDenied`. Anything else — the service not running among them — is `Failed`. The property
buffer is sized by a first call with no buffer, as the documentation describes ("You can set this
parameter to **NULL** to determine the required buffer size"), allocated with pointer alignment, and
the returned string is read only inside that buffer.

**`FixtureHost`** describes the service in an `event_log_channels:` block — a map from channel name
to `log_file_path` and `max_size_bytes`. No block at all is `Unsupported`, never "no such channel"; a
block that does not name a channel is `Ok(None)`; a channel named in `access_denied` is refused.

### 2. What `evtx` emits

On the account of a log whose records name **exactly one** channel, and only there:

| Field | Value |
|---|---|
| `configured_path` | the path the service states for that channel, as the service spells it — normally beginning `%SystemRoot%`, left unexpanded so a reader sees the configuration and not this program's rewriting of it |
| `at_configured_path` | whether that path, with `%SystemRoot%` or `%windir%` replaced by the Windows directory this collector listed, is the file that was read — ASCII case folded, `/` and doubled separators normalised |
| `max_size_bytes` | the maximum size the service states for that channel |

- **A log with no records names no channel** and gets none of the three. There is no configuration
  to compare, and the file name is not used to guess one — measuring showed the name is derived from
  the channel on that machine, but "derived from" is not something to rely on in a field a rule
  matches.
- **A log whose records name several channels** gets none of them: it is not the file of any one.
- **A channel the service does not have** gets none of them, and is not a gap.
- **A configured path that holds another variable, or is not drive-rooted once expanded**, keeps
  `configured_path` and `max_size_bytes` and omits `at_configured_path`. A `%` alone is not a
  variable: every modern channel's file name contains `%4`, so a `%` starts one only when a name of
  letters, digits and `_`, beginning with a letter or `_`, runs to the next `%`.
- **A channel the service would not describe** gaps all three fields for the run with that failure's
  reason, so a rule on them is `unmeasured` and never `not_found`.

The service is asked once per distinct channel per run. The three fields are in `RECORD_FIELDS`, so
a folder holding no log gaps them with `source_empty`, as it does every other per-log field.

### 3. One rule: `event-log-not-at-configured-path`

`87a53c8f-b0e4-477d-91e7-93b904ba965f`, `match: at_configured_path: false`, `experimental`, `tamper`.

What it shows: a log file whose records all belong to a channel that the Event Log service writes to
a different file. That file is not being added to by Windows. The rule compares **only** what the
service states with the file that was read, and a channel with no stated configuration never reads as
moved — which is the property the brief asked for, and the reason the service's answer was preferred
to any registry key, since most keys state no file at all.

Its `falsepositives`, each an ordinary way the shape arises:

- **Automatic backup when full.** "the Event Log file is automatically closed and renamed when it's
  full. A new file is then started" ([ADMX_EventLog](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-eventlog),
  *Back up log automatically when full*). The renamed file still holds that channel's records.
- **A log saved or exported into the folder**, with Event Viewer or `wevtutil epl`
  ([wevtutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil)).
- **A log moved by an administrator, Group Policy or management software.** The policy "controls the
  location of the log file" (ADMX_EventLog, *Control the location of the log file*), and `wevtutil sl`
  sets it; the file from before stays where it was, with the records written until the change.
- **A log copied from another PC or a backup** to be looked at.

`unmeasured_when: [not_windows, not_admin, access_denied]`, as the log-clearing rules (ADR 0031). A
service that could not be asked — for one, because it is not running — reaches the report as
`read_failed`, which no rule may declare (ADR 0032) and which SS mode always lists. That is the right
weight for a machine whose Event Log service does not answer.

**Confronted.** `baseline-elevated-win11` describes the service's answer for the one channel its log
holds — the path and size measured on the machine above — and its log is named as that path says, so
its account carries `at_configured_path: true` and is one condition from firing (ADR 0033). No
`rules/unconfronted.csv` row is needed.

**`evtx-logs-present` now fires it.** That fixture has always held the LanguagePackSetup sample under
the names `Application.evtx` and `Security.evtx`, and has always said so. Describing the service for
that channel makes both files what they are — files that are not where their channel is written — and
the report snapshot shows the rule `found` with both. Its SS snapshot therefore now contains the
channel's name, inside that rule's evidence and nowhere else; the test asserts exactly that.

### 4. No rule on the maximum size

`max_size_bytes` is emitted and **nothing matches it**, because no threshold for "unusually small" can
be defended:

- **The documented minimum is the ordinary value.** `wevtutil`: "The minimum log size is 1048576 bytes
  (1024KB) and log files are always multiples of 64KB". 1 166 of 1 243 channels on the machine measured
  sat at 1 052 672 — the floor rounded to that multiple. A rule below the floor could never fire; a rule
  at the floor would fire on nearly every channel of an ordinary PC.
- **The documented defaults disagree with each other and with the machine.** The policy CSP says the
  Security log "defaults to 20 megabytes" and the Application and System logs default "to 1 megabyte"
  ([EventLogService](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-eventlogservice));
  the Eventlog Key page says `MaxSize` "The default value is 1MB"; the machine had all three at 20 MiB.
  A per-channel "below its default" rule would need a default nobody documents consistently.
- **Legitimate software sets small sizes**, on the evidence of the registry values above, and
  organisations and optimiser scripts change sizes in both directions.

The number is there for a person reading Self mode, and for a later rule that brings a population and
a documented default with it.

## What was rejected

| Alternative | Why not |
|---|---|
| Read `File` and `MaxSize` from `Services\EventLog` | Documented, and states a file for 4 logs of 413 on the machine measured; its `MaxSize` disagreed with the effective size on 4 of 10; `Security`'s key is unreadable under a limited token |
| Read `WINEVT\Channels\<channel>` as well | Undocumented; no `File` value on any of 1 232 keys; `MaxSize` disagreed with the effective size on 14 of 84 |
| Read the policy key as well | Documented key, undocumented value names for these two settings, and no ADMX on the machine to read them from |
| Precedence across the three keys | A precedence this program invented, over sources that each disagree with the service |
| Derive a channel's default file name from its name (`/` → `%4`) and compare that | True on every channel of one machine and documented nowhere; a guess in a field a rule matches |
| `EvtOpenChannelEnum` and a configuration for every channel | ~1 200 channel names is an inventory of installed software, which ADR 0028 declined to report |
| Ask on the parse worker thread, inside the budget | The host is not `Send`, and the collector's budget protects against the parser, not against the service (see below) |
| A `max_size_bytes` rule at the documented minimum, or below 20 MiB for `Security` | See section 4 |

## What is unverified

- **One machine.** The 148/148 comparison, the size distribution and the file-name pattern are one
  Windows 11 installation. Whether an OEM image, a Windows edition or a common application leaves a
  channel's file elsewhere is not established.
- **Whether the positive shape looks like this on a real machine.** No log on the test machine was
  exported, moved, archived or reconfigured to see the rule fire — that would have changed the
  machine. The positive case is proven against fixtures only; the negative case against one machine.
- **Whether `EvtOpenChannelConfig` can block.** The calls are local RPC to the Event Log service and
  run on the collector's own thread, outside `PARSE_BUDGET`. A service that accepts the call and never
  answers would stall the scan, and the desktop app scans before it shows a window (ADR 0024). Nothing
  here measured a hung service, and nothing bounds it.
- **The failure codes.** That a missing channel yields `ERROR_EVT_CHANNEL_NOT_FOUND` wrapped as an
  `HRESULT`, and a refusal `ERROR_ACCESS_DENIED`, is read from the `windows` 0.62.2 constants and the
  .NET wrapper's behaviour on the test machine, and exercised by a live test on the Windows CI runner
  for the missing case only.
- **An exported or archived log's own header.** Whether Windows writes such a file with records whose
  `Channel` element is the original channel is assumed from how the export is described, not checked.
- **Channel names with non-ASCII letters.** The comparison folds ASCII case only, as Windows paths are
  compared elsewhere in this program (ADR 0025); a path differing only in the case of a non-ASCII
  letter would read as a different file.

## Consequences

- `Host` gains the supertrait `EventLogConfigSource`; `LiveHost`, `NonWindowsHost` and `FixtureHost`
  implement it. `rongroi-host-windows` enables the `Win32_System_EventLog` feature of `windows` and
  contains the new `unsafe`, each block with its `SAFETY` comment. No dependency is added and
  `Cargo.lock` does not move.
- `evtx` declares three more fields. Report snapshots gain the rule's row on every host; on the hosts
  with no `%SystemRoot%` it is `unmeasured / read_failed`, as the log-clearing rules' rows are.
- The consent question, the desktop consent screen, `PRIVACY.md` and `docs/architecture.md` say that the
  file and size Windows sets for each log are read.
- ADR 0028's "`maxSize` is not read" is no longer true; its conclusion — that the bytes alone cannot
  separate cleared, rotated and never-enabled — is unchanged, because this ADR adds the configured size
  and does not add any rule that uses it.
