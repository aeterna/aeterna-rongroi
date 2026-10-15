# ADR 0071 — How Windows started, one number of one event

- Status: accepted — the owner approved reading this one value on 2026-10-15, as step 4 of the DMA plan
  (ADR 0069, ADR 0070); implemented the same day ("As built")
- Date: 2026-10-15
- Amends: ADR 0018 (a third kind of event whose payload is read), ADR 0024 (a second reader of `System.evtx`)

## Context

ADR 0069 measured what the times `pci_device` reports mean, and found that one of them depends on how
Windows was last shut down:

| Shut down | A PCI device removed while Windows was off | Measured |
|---|---|---|
| fully, or restarted | absent; `last_arrival_at` is the last start it was present at; **no** `last_removal_at` | VM, S2 |
| with Fast Startup on (the default) | absent; `last_removal_at` is written during the shutdown; the next start does not write `last_arrival_at` again | VM, S5–S6 |

So an absent device with no removal time says nothing about *when* it left unless a reviewer knows which
kind of shutdown came before. Without that, ADR 0070's timeline shows two different situations the same
way.

Windows records which kind it was. At each start, `Microsoft-Windows-Kernel-Boot` writes event 27 to the
`System` log, with `BootType` in its data. The value was measured in the ADR 0069 virtual machine (Windows 11
Arm 26300, `vmprobe.ps1` reading the newest 27 with `Get-WinEvent`):

- `BootType=0` at every start after `shutdown /s` and after a restart: S0, S1, S2, S3, S4, S5, S7.
- `BootType=1` at the start after `shutdown /s /hybrid` (a Fast Startup shutdown): S6. That start wrote no
  new `LastArrival` for any device, which is what ADR 0069 found from the device side.

The same event's data also holds `LoadOptions`, the boot loader's options (measured: ` NOEXECUTE=OPTIN
FVEBOOT=1075351552  NOVGA` and empty). That is not needed and is not read.

### Where this meets this project's own rules

ADR 0018 drops every event's payload, and ADR 0064 widened that for exactly two kinds of PowerShell event.
`BootType` is a payload field, so reading it is a third widening, and this ADR is the review ADR 0018 asks
a payload field to have. It is the smallest one yet: one number of one event, with no text, no name, no
path and nothing a person typed.

## Decision

### 1. A parser function that reads one number

`rongroi_parsers::evtx::windows_starts` reads one log and returns, for each record whose provider, channel
and id are `Microsoft-Windows-Kernel-Boot`, `System` and 27 together (ADR 0031), its time and `BootType` as
a number. A value that is not a number from 0 to 255 is `None`, and the start is still kept. No other value
of that record, and nothing of any other record, is read; `records` is unchanged. The function is in the
fuzz target beside the other two.

### 2. A collector, `windows_start`, standard tier

One observation per start: `started_at` (the record's time) and `boot_type` (the number, absent when there
was none). It reads `%SystemRoot%\System32\winevt\Logs\System.evtx` itself, parsed on its own thread within
`evtx::PARSE_BUDGET`, for the reason ADR 0024 gives: a parse that does not return costs this collector its
run, not the scan. The log not there is `source_absent`; denied without an elevated token is `not_admin`, as
`evtx` classifies it (ADR 0024); a log past the host's 64 MiB limit, any other failure, a parse error or the budget running out is
`read_failed`. The collector gives no meaning to the number.

It is a separate collector rather than a field of `evtx`'s observations because `evtx` groups records by
identity and keeps no per-record value (ADR 0024), and because `records` stays the function that reads no
payload at all, as ADR 0064 kept it.

### 3. Two timeline selectors

The meaning lives in the rules (ADR 0002):

- `windows_start/timeline/full-start` — `boot_type: 0`, "Windows started after a full shutdown or a restart".
- `windows_start/timeline/fast-startup-start` — `boot_type: 1`, "Windows started after a Fast Startup
  shutdown".

Both are `context`, `experimental`. Any other value matches neither and stays in the unmatched list (ADR
0014). On the timeline, a reviewer reads an absent device's last arrival next to the starts around it: a
full start just after it, and no removal time, is the S2 case; a Fast Startup start and a removal time just
before it is the S6 case.

### 4. Consent and privacy

The consent text and `PRIVACY.md` name it: "how Windows started each time its System log remembers — one
number per start, nothing else of the event". The `evtx` consent line ("not what the events say") stays
true of every other event, and `PRIVACY.md` says this is the exception.

## What this does not do

- It does not say a shutdown was chosen to hide anything. Fast Startup is the default, and Windows Update
  restarts are full starts.
- It does not read `LoadOptions`, the boot loader's settings, or any other Kernel-Boot event.
- It does not join a start to a device in the core. The two are side by side on the timeline; a
  cross-source statement (ADR 0061 §3, ADR 0062) is the next step if reviewers find the pairing hard to
  read, and is not built here.

## Alternatives weighed

- **A `boot_type` field on `evtx`'s summaries.** Rejected: a summary is a group of records by identity
  with a first and last time, and a number per record does not fit it; it would also make `records` read
  a payload.
- **`HiberbootEnabled` from the registry.** Rejected as the only source: it says whether Fast Startup is
  on now, not how each past shutdown went, and `shutdown /s /full` or a restart ignores it.
- **Kernel-General 12/13 (start and shutdown times).** They are already in `evtx`'s summaries by identity
  and carry no kind.

## What is unverified

- `BootType=2` (documented elsewhere as a resume from hibernation) was not produced and is not given a
  rule.
- The values were measured on Windows 11 Arm build 26300 in a virtual machine only. On x64 hardware, and
  on Windows 10, they are expected to be the same and were not measured.
- Whether `System.evtx` can be read without an elevated token was not measured for this collector.
- The cost of parsing `System.evtx` a second time was not measured on a full-size log; it is bounded by the
  same budget as `evtx`'s parse.

## Consequences

- A third payload field is read. Every further one needs its own ADR, as ADR 0018 says.
- 68 rules after ADR 0070, 70 with these two. Every older report gains one `windows_start` run.
