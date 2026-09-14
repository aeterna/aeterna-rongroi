# Fixture hosts — provenance

Every host in this folder is **synthetic and hand-written**. None was captured from a real machine, so
none contains a real person's user name, host name, SID or files.

| Host | Describes | Used by |
|---|---|---|
| `secure-boot-on` | Windows 11, Secure Boot reported on | posture collector tests, report snapshots |
| `secure-boot-off` | Windows 11, Secure Boot reported off; the one host that describes how long Windows has been counting since it started (an invented 3 days, 2 hours, 3 minutes and 4 seconds), so that the report snapshots carry a measured boot time as well as an unmeasured one (ADR 0039) | posture collector tests, report snapshots |
| `secure-boot-unreported` | Windows 10, Secure Boot state key absent (e.g. legacy BIOS boot), and so no firmware variables either (`firmware: not_uefi`, ADR 0038) | posture collector tests, report snapshots |
| `registry-access-denied` | Windows 11, Secure Boot key unreadable | posture collector tests |
| `test-signing-on` | Windows 11 with test signing switched on; everything else ordinary | posture collector tests |
| `tpm-absent` | Windows 11 with no TPM, so no specification version either; everything else ordinary | posture collector tests |
| `fivem-dir-plugin-present` | Windows 11, FiveM for GTA V Legacy installed; its plugin folder holds a file whose hash and signature can be read (an empty file, so nothing is embedded), a file whose hash and signature cannot, and a subdirectory. Enhanced is not installed | `fivem_dir` collector tests, report snapshots |
| `fivem-dir-signatures` | Windows 11, Legacy's plugin folder holding one file for each answer a signature check gives (ADR 0035). Every hash, the signing certificate's included, is invented, and `Example Signer` is nobody | `fivem_dir` collector tests |
| `fivem-dir-enhanced-asi` | Windows 11 with only FiveM for GTA V Enhanced: one file in `%APPDATA%\FiveM for GTAV Enhanced\gta5enhanced\asi`, and one in the `mods` folder beside it, which the collector does not read (ADR 0035) | `fivem_dir` collector tests |
| `fivem-dir-client-exe` | Windows 11 with both FiveM editions, each program folder holding `FiveM.exe` beside the other entries a real one has (ADR 0036): Legacy's validly signed and spelled in lower case, Enhanced's with nothing embedded, and `modify.exe` beside it, which is never reported. Every hash and certificate is invented, and `Example Signer` is nobody | `fivem_dir` collector tests, report snapshot tests |
| `fivem-dir-client-folder-denied` | Windows 11, Legacy installed with an empty plugin folder and its program folder, where `FiveM.exe` is, unreadable | `fivem_dir` collector tests, report snapshot tests |
| `fivem-dir-not-installed` | Windows 11 with neither FiveM edition: `%LOCALAPPDATA%` and `%APPDATA%` are set and neither plugin folder exists | `fivem_dir` collector tests |
| `fivem-dir-empty-plugins` | Windows 11, FiveM installed with an empty plugin folder | `fivem_dir` collector tests |
| `fivem-dir-access-denied` | Windows 11, FiveM's plugin folder present but unreadable | `fivem_dir` collector tests |
| `process-own-trace` | Windows 11 running three processes: one whose image path cannot be resolved, one ordinary program, and aeterna-rongroi itself | `process` collector tests, report snapshots |
| `pca-files-present` | Windows 11 with all three PCA files present and readable, their bytes taken from `fixtures/parsers/` | `pca` collector tests, report snapshots |
| `pca-not-present` | **Windows 10 22H2 (build 19045)**, which predates `C:\Windows\appcompat\pca` entirely — the folder arrived in Windows 11 22H2, build 22621. Still a large share of gaming PCs, and on every one of them the artifact's absence carries no information | `pca` collector tests |
| `pca-folder-absent` | Windows 11 24H2 — a build that does keep the files — with no `appcompat\pca` folder at all | `pca` collector tests |
| `pca-folder-empty` | Windows 11 24H2 whose `appcompat\pca` folder is there and holds none of the three files: a machine that keeps this artifact and has written nothing into it. A clean install reaches this on its own, and PCA records only launches made from File Explorer, which is not how a game started by Steam or Epic is launched | `pca` collector tests |
| `pca-access-denied` | Windows 11, the PCA folder present and unreadable, by a process without administrator rights | `pca` collector tests |
| `pca-file-unreadable` | Windows 11 with one PCA file listed and holding no bytes and one that is readable | `pca` collector tests |
| `pca-malformed-lines` | Windows 11 whose launch dictionary has good lines, a line with no delimiter, an impossible date, an empty path and a blank line | `pca` collector tests |
| `pca-utf16-file` | Windows 11 whose launch dictionary is UTF-16 with a byte order mark — not a PCA text file at all | `pca` collector tests |
| `pca-unredactable-path` | Windows 11 whose launch dictionary holds one drive-rooted path, one UNC path and one device path; only the first is a shape SS-mode redaction can reach | `pca` collector tests |
| `prefetch-files-present` | Windows 11 with a readable Prefetch folder holding one `.pf` file, whose bytes are the vendored Windows 10 corpus file and which is not read-only, plus the `ReadyBoot` directory and a non-`.pf` file that a real folder also has | `prefetch` collector tests, report snapshots |
| `prefetch-not-present` | Windows with no Prefetch folder at all and no `EnablePrefetcher` value to explain it | `prefetch` collector tests |
| `prefetch-folder-empty` | Windows 11 whose Prefetch folder is there, is readable and holds no `.pf` file, with `EnablePrefetcher` at Windows' default of 3. The state a "delete Prefetch for FPS" tip, a one-click optimiser or natural eviction at the 1024-file cap leaves — all ordinary on a gaming PC and none of them a statement about what ran | `prefetch` collector tests |
| `prefetch-service-disabled` | Windows 11 with `EnablePrefetcher` at 2 — boot only. Windows writes no application-launch record at all and keeps whatever was written before the switch changed, so the folder is **not** empty and still answers nothing about what ran | `prefetch` collector tests |
| `prefetch-access-denied` | Windows 11, the Prefetch folder present and unlistable, by a process without administrator rights — the expected shape of an ordinary scan (ADR 0015) | `prefetch` collector tests |
| `prefetch-access-denied-elevated` | The same denial with those rights already held, where restarting as administrator would not help | `prefetch` collector tests |
| `prefetch-file-unreadable` | Windows 11 with one `.pf` file listed and holding no bytes and one that is readable | `prefetch` collector tests |
| `prefetch-unsupported-version` | Windows 11 whose Prefetch folder holds one SCCA v26 file from an older Windows, which this parser does not decode | `prefetch` collector tests |
| `prefetch-corrupt-files` | Windows 11 whose Prefetch folder holds an intact `MAM` container over a payload that is not Xpress-Huffman, and the corpus's deliberately bad file | `prefetch` collector tests |
| `registry-bytes-present` | Windows 11, one registry key holding a binary value whose bytes come from `fixtures/parsers/bam/documented-24-byte-value.bin`, one written inline, and one described without bytes — a value that is there and cannot be read | `rongroi-host` fixture tests |
| `bam-entries-present` | Windows 11 whose BAM state holds one account with two executables in it, their value bytes taken from `fixtures/parsers/bam/`, beside the account key's own `Version` and `SequenceNumber` with measured numbers (below) | `bam` collector tests, report snapshots |
| `bam-account-metadata` | Windows 11, build 26220, two accounts whose keys both hold `Version` and `SequenceNumber` as `REG_DWORD` with measured numbers (below), one of them beside a record and the other holding nothing else — the two shapes an account key was measured in | `bam` collector tests |
| `bam-device-paths` | The same with the value name spelled as a device path, the form no SS-mode redaction can reach | `bam` collector tests |
| `bam-two-accounts` | Two accounts with BAM records, so that the report's count of them can be asserted and their SIDs asserted absent | `bam` collector tests |
| `bam-not-present` | A Windows machine with no BAM state at all: the service is not there, or this build never had it | `bam` collector tests |
| `bam-empty` | The BAM key present and holding no account — a machine whose execution history was cleared | `bam` collector tests |
| `bam-access-denied` | Windows 11, the BAM key present and unreadable, by a process without administrator rights | `bam` collector tests |
| `bam-access-denied-elevated` | The same denial with those rights already held, where restarting as administrator would not help | `bam` collector tests |
| `bam-account-denied` | Two accounts, one of whose keys cannot be read, so an unknown number of records is missing | `bam` collector tests |
| `bam-malformed-value` | One account holding a value that decodes, one a byte short of a timestamp, and one that is there and has no bytes | `bam` collector tests |
| `bam-longer-value` | A BAM value longer than the public write-ups describe, as a newer Windows build might write | `bam` collector tests |
| `evtx-logs-present` | Windows 11 with a readable Event Log folder holding two `.evtx` files, both referencing the one vendored Event Log sample and neither read-only, plus a file that is not a log. It describes what the Event Log service states for the sample's channel, so both files — named `Application.evtx` and `Security.evtx`, holding LanguagePackSetup records — are files that are not where their channel is written (ADR 0042) | `evtx` collector tests, report snapshots |
| `evtx-not-present` | Windows with no Event Log folder at all, so nothing can be said about what any log holds | `evtx` collector tests |
| `evtx-logs-folder-empty` | Windows 11 whose Event Log folder is there, is readable and holds no `.evtx` file — the shape a one-click maintenance script leaves when it clears every log, and the shape Microsoft's own "delete corrupt Event Viewer log files" remedy leaves. The one file in it is not a log | `evtx` collector tests |
| `evtx-access-denied` | Windows 11, the Event Log folder present and unlistable, by a process without administrator rights — the expected shape of an ordinary scan (ADR 0018) | `evtx` collector tests |
| `evtx-access-denied-elevated` | The same denial with those rights already held, where restarting as administrator would not help | `evtx` collector tests |
| `evtx-log-unreadable` | Windows 11 with `Security.evtx` listed and holding no bytes and `Application.evtx` readable | `evtx` collector tests |
| `evtx-log-truncated` | Windows 11 whose Event Log folder holds a file shorter than the fixed 4 KiB header every `.evtx` begins with | `evtx` collector tests |
| `file-content-present` | Windows 11, one folder holding a file whose bytes are written inline, one whose bytes come from `fixtures/parsers/pca-app-launch/normal.txt`, and one listed without bytes — a file that is there and cannot be read | `rongroi-host` fixture tests |
| `baseline-hardened-win11` | Windows 11 as Microsoft ships it: Secure Boot on, memory integrity configured on, test signing off, TPM 2.0, no FiveM, ordinary programs running | `cargo xtask check-baseline` |
| `baseline-consumer-win11` | Ordinary consumer Windows 11: no memory-integrity policy key at all, FiveM installed with an empty plugin folder and `FiveM.exe` as measured (below) | `cargo xtask check-baseline` |
| `baseline-elevated-win11` | The ordinary Windows 11 PC of a FiveM player, scanned after the restart-as-administrator offer was accepted: `baseline-hardened-win11`'s posture, FiveM installed with an empty plugin folder and `FiveM.exe` as measured (below), and PCA, Prefetch, the Event Log folder and the BAM state key all present and readable. Its `EnablePrefetcher`, its files' read-only attribute and the Event Log service's answer for its one channel are measured values (below) | `cargo xtask check-baseline` |

**`FiveM.exe` in `baseline-consumer-win11` and `baseline-elevated-win11` is measured, not written.**
Measured 2026-09-13 on one Windows 11 machine, build 26220, read-only, with `Get-FileHash`,
`Get-AuthenticodeSignature` and this program's own signature check, elevated and under a limited token
(ADR 0036): Legacy's `%LOCALAPPDATA%\FiveM\FiveM.exe` as FiveM installed and updated it, its SHA-256
`891e48128dc9c287aaa204757acac61d469eef9de82714cec4404d254a73c844`, an embedded signature that is valid,
signer "Rockstar Games, Inc.", signing certificate SHA-256
`65866007102ff66498c1ef739cf23dff71ae3d08da0d9d759b89d1a409c4208f`, and `FiveM.app` beside it. Enhanced's
`FiveM.exe` on the same machine carried the same certificate; neither baseline describes Enhanced. The
file's hash identifies a FiveM build that Cfx.re distributes to everyone, not the machine; no path, user
name or other file from that machine is in the fixture. Only the entries the collector reads are
described — the folder's shortcut and manifest are left out, as the collector never reports them. What
this does not claim: that a player's `FiveM.exe` has this hash — it changes with every FiveM update —
or that the certificate stays the same after 2027-09-05, when it expires.

**Firmware and the PowerShell logging policy (ADR 0038).** Every `elevated: false` host that describes
posture — `secure-boot-on`, `secure-boot-off`, `test-signing-on`, `tpm-absent`,
`registry-access-denied`, `baseline-hardened-win11` and `baseline-consumer-win11` — declares
`firmware: { secure_boot: access_denied }`, and `baseline-elevated-win11` declares `enabled`. Both values are
**measured**, not chosen: on 2026-09-13, one Windows 11 machine (build 26220), the CLI's firmware reading was
`not_admin` under a limited token and `enabled` elevated, and PowerShell's `Get-SecureBootUEFI` read the same
variable as the single byte `01`. No baseline writes a `ScriptBlockLogging` key, so all three report
`script_block_logging: not_configured`. That absence is what the same machine held, under `HKLM` and under
its account's `HKCU`, and what Microsoft's own enabling snippet assumes: it creates the key when `Test-Path`
says it is not there ([about_Logging](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging?view=powershell-5.1)).
One machine is one machine: none of these values is a statement about how other firmware answers.

No baseline writes PowerShell 7's `PowerShellCore\ScriptBlockLogging` key or either policy key under `HKCU`
either, so `script_block_logging_user`, `script_block_logging_pwsh` and `script_block_logging_pwsh_user` are
`not_configured` on all three (ADR 0038, amended 2026-09-14). What that rests on: the machine above held no
PowerShell 7 key under `HKLM` (its `HKCU` PowerShell 7 key was not looked at); the GitHub `windows-latest` runner
on 2026-09-14 (build 26100, Windows PowerShell 5.1 and PowerShell 7.6.5) held none of the four keys before the CI
step wrote any; and Microsoft's PowerShell 7 enabling snippet also creates its key when `Test-Path` says it is not
there ([about_Logging_Windows](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows?view=powershell-7.5)).
A runner is an imaged virtual machine, not a player's PC.

A host named `baseline-*` is read by `cargo xtask check-baseline` and means more than the others: it
asserts that a machine like this is unremarkable, so the whole rule set must stay quiet on it (ADR 0017).
Each one is a written profile; a setting in it is never changed to silence a rule.

**What a baseline leaves out is a claim too.** A source a baseline does not describe is not read, the
collector is `Unmeasured`, and a rule for it passes the gate whatever it says — which is what
`baseline-consumer-win11` and `baseline-hardened-win11` do to `pca`, `prefetch`, `bam` and `evtx`: neither
sets `WinDir` or `SystemRoot` and neither carries a BAM key. `baseline-elevated-win11` was added for that
(ADR 0026) and is the host on which every collector in the build is `Measured` with no gaps. Its artifacts
hold the shapes a careless rule fires on — a game executable run from a Downloads folder, `cmd.exe` with a
Prefetch record, a BAM entry whose path is a device path — because leaving those out would make the claim
weaker, not safer.

**Three things about `baseline-elevated-win11` are the fixture's shape rather than an ordinary machine's**,
and a rule keyed on them is not meaningfully measured there. It holds **one** `.evtx` file where a real
`winevt\Logs` holds on the order of a hundred, and **one** `.pf` file where a real Prefetch folder holds
hundreds, because this repository vendors exactly one modern sample of each and every other candidate
carried somebody's data (`fixtures/evtx/PROVENANCE.md`, `fixtures/prefetch/PROVENANCE.md`); so `logs: 1`,
`examined: 1` and `files: 1` are artefacts of that. And the one event log is
`Microsoft-Windows-LanguagePackSetup/Operational`, so event ids 4000 and 4001 are the only ones any rule can
be measured against — the `Security` channel, which ADR 0018 and ADR 0024 were written for, is not
represented. Its log file is named after the channel its records declare, deliberately: a log whose records
name a different channel is a file that was *put* there, and a baseline showing that shape would be
asserting it is unremarkable.

**It is `elevated: true`, and that is the claim, not a convenience.** This repository does not say any of
those four sources is readable without an elevated token — ADR 0021 and ADR 0024 say the opposite for
Prefetch and for `Security.evtx`, ADR 0020 and ADR 0023 record PCA and BAM as unestablished — so a
non-elevated host that read them all would assert something nobody here has measured. The two existing
baselines stay `elevated: false` and remain the only description of a non-elevated scan.

**Measured values in `baseline-elevated-win11`.** Five things in that host are not invented and not
documented by Microsoft; each was read from one Windows 11 machine (build 26220, elevated, read-only, on
2026-09-13, the BAM values on 2026-09-14) and nothing on that machine was changed:

| Value in the host | What was measured |
|---|---|
| `EnablePrefetcher: 3` | the value in `PrefetchParameters`, a `REG_DWORD` (ADR 0037) |
| `read_only: false` on the `.pf` file | 239 `.pf` files, none read-only (ADR 0037) |
| `read_only: false` on the `.evtx` file | 413 `.evtx` files, none read-only (ADR 0037) |
| `Version: 1` and `SequenceNumber: 115` in the BAM account key | the two `REG_DWORD` values every one of the machine's 7 account keys held beside its records: `Version` was 1 in all 7 and `SequenceNumber` between 59 and 170, of which 115 is one. A 0.2.0 report from a second Windows 11 machine (build 26200) is consistent with the same pair in its 8 account keys — 16 refused values whose names were not drive-rooted — though a report names neither the values nor their accounts. Microsoft documents neither (ADR 0023, amendment of 2026-09-14). `bam-entries-present` carries the same pair, and `bam-account-metadata` it and the measured 59 |
| `event_log_channels` for `Microsoft-Windows-LanguagePackSetup/Operational`: `log_file_path` `%SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-LanguagePackSetup%4Operational.evtx`, `max_size_bytes` 1052672 | what the Event Log service stated for that channel; 1 166 of the machine's 1 243 channels had that size, and every channel's file was its name with `/` written `%4` (ADR 0042) |

`evtx-logs-present` and the temporary hosts the `evtx` tests build describe the service with the same
measured answer. One machine is one machine: these are values an ordinary PC was seen to have, not the
only values an ordinary PC has.

The user name `fixtureuser` in these paths is invented; it exists so that SS-mode redaction has something
to replace.

A file entry may carry its bytes as well as its hash (ADR 0019): `content:` writes them inline, and
`from:` names a file relative to the host's own directory, which is how a host reaches the artifact
corpora in `fixtures/parsers/`, `fixtures/prefetch/` and `fixtures/evtx/`. Those corpora are inputs and
are never written to; a host points at them and copies nothing.

A registry value carries its bytes the same two ways (ADR 0022): a value written as a map with
`content:` or `from:` is a `REG_BINARY`, a number is a `REG_DWORD` and a string is a `REG_SZ`. A value
written as an empty map is there and cannot be read.

The account names `alex`, `shareduser` and `deviceuser` that reach these hosts are invented in the same way,
`alex` through the parser corpora in `fixtures/parsers/` and the other two inline in `pca-unredactable-path`
and `bam-device-paths`. So are `otheruser` and every SID in the `bam-*` hosts: the SIDs are written out in
full there deliberately, so that a test asserting no part of one reaches an observation has something to
assert against.
They are there so that a test can assert a name never reaches an observation.

**One set of bytes carries a real account name**: the `prefetch-*` hosts and
`baseline-elevated-win11`, which point at
`fixtures/prefetch/win10-compressed-v30-CMD.EXE-D269B812.pf`, inherit that file's string table,
which holds the upstream author's one-letter account name and his machine's volume serial numbers
(`fixtures/prefetch/PROVENANCE.md` records why it was vendored anyway). A one-letter name cannot be
asserted absent — `contains("a")` is true of almost any JSON — so the `prefetch` collector's tests
assert the *shapes* instead: no `\USERS\`, no `VOLUME{`, no `HARDDISKVOLUME` and no `.DLL` in the
serialised observations, and no `loaded_files` or `volumes` field under any name. The collector
emits neither field at all, which is what makes those assertions meaningful rather than lucky (ADR
0021).

**The `evtx-*` hosts and `baseline-elevated-win11` reach a real host name**, `DESKTOP-1N4R894`, in
the chunk string table of `fixtures/evtx/languagepacksetup-operational.evtx` — the one Event Log
sample this repository vendors, and a name Windows generates at install time
(`fixtures/evtx/PROVENANCE.md` records why it was vendored anyway and counts every other string in
the file). Unlike the Prefetch account name, 15 characters can be asserted absent and are, in the
`evtx` collector's tests and in the report snapshot test. That assertion alone would not catch a
payload leak, so the element names and payload fragments the file also holds — `EventData`,
`Computer`, `UserID`, the `ping-response` fragments, the `MS-CV` tokens — are asserted absent beside
it (ADR 0024). The parser drops every record's payload before the collector sees it (ADR 0018).

Two `evtx` tests build a fixture host in the temporary directory instead of reading one from here: a
damaged chunk and a file whose header is not an Event Log's. Neither may be committed to
`fixtures/evtx/`, which is the seed corpus `fuzz_evtx` reads and where everything has to parse, and an
`.evtx` file is binary, so neither can be written inline in a `host.yaml` the way `prefetch-corrupt-files`
writes its bytes.

When a fixture is generated from a real Windows install (M2 onwards), record here: what generated it, the
Windows build, that networking was disabled, and who checked it for a real user name, host name or SID, and
how. Neither `tools/fixture-gen/` nor `cargo xtask scrub-check` exists — ADR 0016 counts both among the
promises this repository has made with no code behind them, and `CONVENTIONS.md` §4 records the gap — so
that last check is a person's.
