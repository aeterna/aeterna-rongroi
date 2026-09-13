# ADR 0010 — The process source, and the tool's own traces

- Status: accepted
- Date: 2026-09-12

## Context

Every source so far reads a value someone named in advance: a registry value, a directory, an
environment variable, the kernel's code-integrity word, the TPM's identity. The list of running
processes is the first source that **enumerates operating-system objects** — the collector does not
know what it will find, and what it finds includes things nobody wrote a rule about.

It also includes aeterna-rongroi. The program is running while it scans, so its own process is in
the list it reads, and one of the observations the `process` collector produces describes the tool
rather than the machine. Both of those are new, and they arrive together because the second has no
other trigger: without a collector that enumerates, nothing in the report is ever about the tool.

## Decision

### The `process` source lists, and reads nothing else

`Host` now also requires `ProcessSource` (`running_processes`), returning `pid`, `name` and an
optional `path` per process. `LiveHost` takes a ToolHelp process snapshot and asks each process for
its image path with `PROCESS_QUERY_LIMITED_INFORMATION`, the smallest access right that answers
"what is this process"; it needs no administrator rights. Every handle — the snapshot and each
opened process — is closed on every path out.

Nothing else is read. No image is hashed, no process memory is touched, and no handle outlives the
one query that needs it. Hashing every running image on every scan is the expensive reading of
"light" and nothing in the design asks for it; if a digest is wanted later, the existing
`FilesystemSource::file_sha256` supplies one without a new capability.

The `windows` 0.62.2 features this needs — `Win32_System_Diagnostics_ToolHelp` for
`CreateToolhelp32Snapshot` and the `Process32*W` walk, `Win32_System_Threading` for `OpenProcess`
and `QueryFullProcessImageNameW` — were read from that crate's own manifest, as ADR 0011 said they
must be. `CloseHandle` comes with `Win32_Foundation`, which was already enabled.

### A process that cannot be named is still listed

A protected process, and one that exits between the snapshot and the query, has no path to report.
That observation is emitted with `name` and without `path`. This is the per-item rule ADR 0009 set
for `fivem_dir`: `gaps` describes the whole run and cannot say "item 7 of 40 failed", so a per-item
failure omits a field, never invents one, and never hides the item. Dropping the process would
understate what is running, which is the one thing this collector exists to state.

A snapshot that cannot be taken at all is the opposite case: `Unmeasured { read_failed }` for the
whole collector. `Measured` with nothing in it would read as "this machine was running no
processes", which no machine ever is.

### Observations carry `name` and `path`, not `pid`

`ProcessRecord` carries the pid because `OpenProcess` needs it, but the observation does not. No
rule can usefully match a number that changes on every boot, and collectors collect only what a rule
needs (`crates/rongroi-collectors/AGENTS.md`). Two processes of the same name and path therefore
produce two identical observations, which is the honest statement that two of them are running.

### Own traces are a visible bucket, not a deletion

`Report` gains `own_traces: Vec<OwnTraceEntry>`, and `evaluate` moves every observation that
describes the running executable — by `path`, or by `sha256`, compared without regard to ASCII case
— out of the runs and into it before any rule is evaluated.

The alternative was to drop those observations. That would have made the report *look* like a report
about the machine while quietly editing what the collectors saw, and a reader could not tell the
difference between "the tool excluded itself" and "the tool was never there". Showing the bucket
costs a few lines and says exactly what happened. Leaving them in the evidence was never an option
either: a rule about a running program would match the scanner itself, and the report would accuse
the tool of being on the PC it is examining.

The field is additive and `REPORT_SCHEMA_VERSION` does not change: a report written before it
existed reads back with no own traces, which is what it meant.

### Removing an observation must not change what the run means

A run whose only observation was the tool's own becomes `Measured` with an empty observation list —
it keeps its shape, its collector id and its `gaps`. A rule on that collector is then `NotFound`:
the collector did look, and found nothing that was not us. Turning it into `Unmeasured`, or dropping
the run, would claim the collector could not look, which is a different and false statement. There
is a test for exactly this, with its positive twin — the same run, a process that is not ours,
`Found` — so that the `NotFound` cannot be coming from a rule that never matches at all.

### `SelfIdentity` travels in `ScanContext`; `evaluate_rule` does not change

`SelfIdentity { exe_path, exe_sha256 }` is computed by each binary's `main` and carried in
`ScanContext`. `scan::run` does **not** call `std::env::current_exe()`.

Reading the identity ambiently from the running process would make the whole behaviour untestable
below the unit-test level: a fixture cannot portably name the test binary's own path, so no snapshot
could ever exercise the separation. Passing it in costs a few lines in two `main` functions and buys
a fixture that proves the whole pipeline. The digest is the one `Provenance` already computed for
the report header, so the executable is not read twice.

Only `evaluate` changes. `evaluate_rule` keeps its signature: `cargo xtask check-rules` calls it
directly for every rule fixture, and a rule fixture must not have to know what executable was
running when it was written.

### Own traces are shown in both modes

SS mode lists `Found` evidence and all `posture` evidence, and counts the rest. `own_traces` is not
evidence about the machine at all, so that filter does not apply to it: hiding "this was us" from
the person watching the screenshare would be less transparent, not more. Path values in it go
through the same redaction as `Found` evidence, so the user-profile folder is replaced there too.

### A fixture's silence about processes is `Unsupported`

`FixtureHost` reads a `processes:` block of `{pid, name, path?}` and returns it in file order. A
fixture with no such block returns `Unsupported`, exactly as ADR 0011 decided for `code_integrity:`
and `tpm:`. The block is therefore `Option<Vec<…>>` rather than a defaulted `Vec<…>`: a defaulted
empty list would make every fixture written before this change assert that the machine was running
no processes, which is the same class of mistake as reporting `NotFound` for something never read. A
fixture that writes `processes: []` makes that claim on purpose, and is tested.

### The privacy gap this does not paper over

SS mode redacts the `X:\Users\<name>\` shape inside path strings. A process **name** is not a path
and is not touched. Some installers and tools produce executables named after the account that
installed them, so a process name can carry a real person's name to an SS-mode viewer unredacted.

There is no general pattern that recognises an account name inside an arbitrary string, and a regex
invented for the purpose would either miss most names or redact ordinary words — a redaction that
looks like a guarantee without being one is worse than none. So two things happen instead, and
nothing more: `PRIVACY.md` states the gap plainly, so a reviewer knows what they may see; and no
`process` rule in this change matches on `name`.

### No rule ships with the collector

The same reasoning as `fivem_dir` (ADR 0009): naming a specific cheat loader needs a cited source,
and this repository does not assert third-party product names without one. A rule decides what is
called out as `Found`; the collector can land, and be tested, before anyone can name something
worth calling out.

## Consequences

- Until a rule reads `process`, nothing from the list reaches a view except the own traces: a
  `Report` holds evidence per rule, and observations reach a view only through `Found`. This is
  already true of `fivem_dir`, whose report snapshot shows no file from the plugin folder. It is
  worth stating rather than repeating the claim that a collector without a rule is "shown in Self
  mode" — today it is not.
- `Report` and `ReportView` both grew a field, which every consumer reads: the CLI prints an "own
  traces (excluded)" section after the evidence, the desktop app renders the same section, and the
  TypeScript mirror of the model gained `OwnTraceEntry`. Every existing report snapshot gained
  `"own_traces": []`.
- The comparison is ASCII-case-insensitive, like the `sha256` comparison in `allow`. A path that
  differs from ours only outside ASCII will not match; it would take a deliberately built path to
  produce one.
- Turning a NUL-terminated UTF-16 buffer into a name is a free function outside the `unsafe` blocks,
  so it is compiled and tested on macOS and Linux as well as Windows — the split ADR 0011 made for
  the TBS result codes. A name that is not valid UTF-16 keeps the process, with replacement
  characters, rather than dropping it.
- The three `unsafe` calls can only be exercised on Windows. They are type-checked for
  `x86_64-pc-windows-msvc` from any operating system and run by the Windows CI job.
