# ADR 0094 — A Windows program's name outside Windows' folders

- Status: proposed. The owner chose the five recommendations behind this ADR on 2026-11-08 (D1–D5 of the plan
  "Rongroi Trace Gaps & Motion"). The text below is approved when the pull request that builds it is reviewed
  (G1 of wave W2). No code is written yet
- Date: 2026-11-08
- Related: AGENTS.md hard rules 3, 5, 6 and 9, ADR 0009 and ADR 0010 (the `fivem_dir` and `process` sources,
  and why neither shipped a rule without a cited source), ADR 0014 (unmatched observations), ADR 0021 and ADR 0023 (Prefetch and BAM paths),
  ADR 0062 (`fivem_edition`, a word derived from a path that is not emitted), ADR 0084 (rule 9 applied),
  ADR 0087 (drive map for device paths)
- Amends: the landing page's row "Programs that ran" (`site/en/index.html`), which says "no rule judges a
  program by its file name". It will say "no rule judges a program by its file name alone". The edit lands in
  the same pull request as the rules

## Context

A player asked about a short video that tells people to check their own PC: open Task Manager, find
`svchost.exe`, open its file location, and treat it as fake if the folder is not `System32`. The technique the
video describes has a public name: MITRE ATT&CK T1036.005, "Match Legitimate Name or Location". A program takes
the name of a Windows program so that a person scrolling a process list does not stop at it.

Three sources already hold what that check needs:

- `process` reports each running program's `name` and, when it can be read, its `path` (ADR 0010).
- `bam` reports `name` and, when the drive map can give it a drive letter, `path` (ADR 0023, ADR 0087).
- `prefetch` reports `name` and the path of the `.pf` file. The executable's own path is in the file's string
  table, and that path is not emitted. `fivem_edition` is already derived from it as one word (ADR 0062).

None of them reports the case the video describes:

- No rule reads `process`. ADR 0010 shipped the collector without one, so the list never reaches a view
  except as the tool's own traces.
- The rule language has no negation. `startswith`, `endswith`, `contains` and `exists` cannot say "the path
  is not below `System32`".
- `bam/ephemeral/executed-program-missing-on-disk` reports a deleted program that ran from Temp, Downloads or
  a removable drive. The same program run from `C:\ProgramData\…` and left on disk is not reported.
- The Prefetch and BAM timeline rules match FiveM's and GTA V's names only.

What the change must not do:

- vouch for anything (hard rule 9). A `svchost.exe` in `System32` is not "genuine" because of where it is;
- use a file name in `allow` (hard rule 6);
- give a verdict or a score (hard rule 3);
- emit a path that SS-mode redaction cannot reach, or a new identifier (hard rule 5, ADR 0023);
- read a process's memory or the modules loaded into it (ADR 0010).

## Decision

### 1. One derived field, `system_name_elsewhere`

`process`, `bam` and `prefetch` gain one boolean field, `system_name_elsewhere`. The collector sets it on an
observation whose program name is in the table of section 4:

- `true` when the program's folder is not one of the folders the table expects for that name and is not a
  servicing folder (section 4);
- `false` when it is one of them;
- omitted when the name is not in the table, or when the program's path cannot be read. This is the per-item
  rule of ADR 0010: a value nobody could read is left out, never guessed.

How the folder is read, per source:

- **`process`**: from `path`, after the existing resolution to drive-letter form.
- **`bam`**: from the value name in whatever form BAM spelled it, device path included, the same way
  `fivem_edition` is read. A path the drive map cannot turn into a drive letter stays withheld (ADR 0087).
  The boolean is still emitted, because it is one word and carries no account name.
- **`prefetch`**: from the executable's own entry in the string table, the same entry `fivem_edition` reads,
  compared below its `\VOLUME{…}` prefix. The entry itself is still not emitted. When more than one entry has
  the executable's name and they disagree, the field is omitted, as `fivem_edition::of_prefetch` does.

Comparison ignores ASCII case. The measurement in section 4 shows Windows itself reporting
`C:\WINDOWS\Explorer.EXE` and `C:\WINDOWS\system32\conhost.exe`. `%SystemRoot%` is read from the machine, not
assumed to be `C:\Windows`.

A derived boolean is the shape `bam` already uses for `disappeared_from_disk`. Adding a `not` operator to the
rule language was the other option. It was not taken: it changes the grammar every rule and fixture is checked
against (ADR 0026), to serve one rule family.

### 2. Three rules, one per source

Each of `process`, `bam` and `prefetch` gets one rule that matches `system_name_elsewhere: true`:

- `strength: context`, `status: experimental`. There is no public report of a FiveM cheat loader doing this
  (section 5), so it is not presented as more than context.
- `references:` cites MITRE ATT&CK T1036.005. The rule names a technique, not a product, which is what
  ADRs 0009 and 0010 ask for before anything is called out.
- `falsepositives:` lists at least an interrupted Windows update or upgrade running from a folder the table
  does not list, a Windows installation on a second drive whose files were run from the first, and a tool that
  ships its own copy of a Windows program under the same name.
- No `allow`. Nothing in these rules is excused by name, hash or certificate.

Each rule carries a positive fixture, a program of a table name in `C:\ProgramData\x\`, and a negative fixture
with the same name in its expected folder (hard rule 6). The `process` rule also gets a negative fixture whose
path could not be read, to show that an omitted field is not matched.

### 3. Why this is not vouching, and not a file-name judgement

- **The table is what the rule expects, not a list of good software.** Hard rule 6 lets `allow` name what a
  rule expects. This rule has no `allow` at all. The table describes where Windows puts its own programs, and
  the rule reports what differs from that.
- **`NotFound` here means this rule found nothing, and no more.** A `svchost.exe` in `System32` gives
  `system_name_elsewhere: false`. It is not folded, hidden, greyed or moved down anywhere. It stays in the
  unmatched observations (ADR 0014), and every other rule that reads the same observation still applies. No
  view and no locale string may call it genuine, Windows', trusted or known.
- **A name is half of the condition.** The rule matches a name together with a folder. The landing page's
  sentence "no rule judges a program by its file name" was true when written and stops being true. It becomes
  "no rule judges a program by its file name alone".

### 4. The table, written by us from a measurement

The names are those most often taken in MITRE's T1036.005 procedure examples and in the public detection
rules listed below. The expected folders were measured on a real machine, not copied:

Measured 2026-11-08 on `pik-windows`: build 26320.9876, DisplayVersion 26H2, x64. The registry's
`ProductName` reads "Windows 10 Home", which is a known leftover on Windows 11 builds; the build number is the
one to read. Method: `Test-Path` on `C:\Windows\System32\<name>`, `C:\Windows\SysWOW64\<name>` and
`C:\Windows\<name>`, plus the image paths of the running `svchost`, `explorer`, `RuntimeBroker`, `conhost` and
`taskhostw` processes.

| Name | System32 | SysWOW64 | `%SystemRoot%` | Expected folders |
|---|---|---|---|---|
| `svchost.exe` | yes | yes | no | System32, SysWOW64 |
| `explorer.exe` | no | yes | yes | `%SystemRoot%`, SysWOW64 |
| `lsass.exe` | yes | no | no | System32 |
| `csrss.exe` | yes | no | no | System32 |
| `smss.exe` | yes | no | no | System32 |
| `wininit.exe` | yes | no | no | System32 |
| `winlogon.exe` | yes | no | no | System32 |
| `services.exe` | yes | no | no | System32 |
| `dwm.exe` | yes | no | no | System32 |
| `conhost.exe` | yes | no | no | System32 |
| `taskhostw.exe` | yes | no | no | System32 |
| `RuntimeBroker.exe` | yes | no | no | System32 |
| `spoolsv.exe` | yes | no | no | System32 |

Running image paths on the same machine: `C:\WINDOWS\Explorer.EXE`, `C:\WINDOWS\system32\conhost.exe`,
`C:\Windows\System32\RuntimeBroker.exe`, `C:\WINDOWS\System32\svchost.exe`, `C:\WINDOWS\system32\taskhostw.exe`.

**Servicing folders** never set the field to `true`, for any name: `%SystemRoot%\WinSxS`,
`%SystemRoot%\SoftwareDistribution`, `C:\$WINDOWS.~BT` and `C:\$WinREAgent`. Windows Update and feature upgrades
stage and run copies of these programs from them.

**Sources, used as cross-references only:**

- MITRE ATT&CK T1036.005: <https://attack.mitre.org/techniques/T1036/005/>
- Sigma `proc_creation_win_susp_system_exe_anomaly`, which also lists the servicing folders. Its licence,
  DRL 1.1, asks for its author to be credited wherever its matches are shown. No Sigma text is copied into
  this repository, so that clause is not taken on.
- Elastic "Potential Masquerading as Svchost" (Elastic License v2), for the two `svchost.exe` folders. Its
  triage notes say a Microsoft signature or a familiar parent does not clear a wrong path.

The table is one list in one collector module, shared by the three sources, with a unit test that pins it to
the table above. A name added later needs a measurement and a line in this ADR's amendments.

### 5. What was looked for and not found

There is no public write-up of a FiveM cheat loader that names itself after a Windows program or runs from
`System32`. Public sandbox reports of FiveM "cheats" show information stealers that switch Defender off and run
obfuscated PowerShell. `powershell_text`, `defender_exclusion` and `posture` already read those traces. The
`svchost.exe` entries in those reports are the real `svchost.exe`. This is why section 2 uses `context`.

The video's other advice, that a "d3dx11 not found" message is a warning sign, is not taken up. The message
means the legacy DirectX End-User Runtime (June 2010), which provides `d3dx11_43.dll`, is not installed. It says
nothing about cheats.

### 6. Left for later

- **The signer of these files** (phase 2, the owner's D3). A file of a table name in `System32` that is not
  signed by the pinned Windows certificate is the case this ADR cannot see. Reading a running image's signature
  is a new reading for `process`, so it amends ADR 0010, in its own ADR. It is limited to the table's names and
  uses `FilesystemSource::file_signature`, which exists.
- **Names one character off** (`svchosst`, `svhost`, `svch0st`): parked (the owner's D4). A fuzzy match would
  fire on gaming tweak tools, and no FiveM case calls for it.
- **Parent process, command line, number of instances.** `svchost.exe` normally starts from `services.exe`
  with `-k`, and there is exactly one `lsass.exe`. Each needs a reading `process` does not make.
- **A DLL loaded into a real `svchost.exe`.** Out of scope. ADR 0010 reads no process memory and no module
  list.

## Consequences

- Three collectors each gain one field. Every report snapshot that holds an observation of a table name gains
  `system_name_elsewhere`. `REPORT_SCHEMA_VERSION` does not change, because the field is additive.
- `process` gets its first rule. ADR 0010's consequence, that nothing from the list reaches a view except the
  tool's own traces, stops being true for observations this rule matches. Every other running program is
  still only unmatched.
- **Privacy.** The names come from a fixed table of Windows programs and cannot carry an account name. A
  matched `path` goes through the same SS-mode redaction as other `Found` evidence. A BAM path that could not
  get a drive letter stays withheld, and only the boolean is reported.
- **Baseline.** `cargo xtask check-baseline` must stay quiet with the three rules. An ordinary Windows machine
  must not match. If it does, that is a false positive to fix in the table or the servicing list before the
  rules ship, never to wave through with `allow`.
- `docs/rules-reference*.md` are regenerated (`cargo xtask rules-reference`), and the rule count in the
  README changes with them.
- The landing page sentence changes, as stated under "Amends".
