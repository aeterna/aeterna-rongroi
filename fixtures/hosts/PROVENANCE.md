# Fixture hosts — provenance

Every host in this folder is **synthetic and hand-written**. None was captured from a real machine, so
none contains a real person's user name, host name, SID or files.

| Host | Describes | Used by |
|---|---|---|
| `secure-boot-on` | Windows 11, Secure Boot reported on | posture collector tests, report snapshots |
| `secure-boot-off` | Windows 11, Secure Boot reported off | posture collector tests, report snapshots |
| `secure-boot-unreported` | Windows 10, Secure Boot state key absent (e.g. legacy BIOS boot) | posture collector tests, report snapshots |
| `registry-access-denied` | Windows 11, Secure Boot key unreadable | posture collector tests |
| `test-signing-on` | Windows 11 with test signing switched on; everything else ordinary | posture collector tests |
| `tpm-absent` | Windows 11 with no TPM, so no specification version either; everything else ordinary | posture collector tests |
| `fivem-dir-plugin-present` | Windows 11, FiveM installed; its plugin folder holds a file whose hash can be read, a file whose hash cannot, and a subdirectory | `fivem_dir` collector tests, report snapshots |
| `fivem-dir-not-installed` | Windows 11 with no FiveM: `%LOCALAPPDATA%` is set and the plugin folder does not exist | `fivem_dir` collector tests |
| `fivem-dir-empty-plugins` | Windows 11, FiveM installed with an empty plugin folder | `fivem_dir` collector tests |
| `fivem-dir-access-denied` | Windows 11, FiveM's plugin folder present but unreadable | `fivem_dir` collector tests |
| `process-own-trace` | Windows 11 running three processes: one whose image path cannot be resolved, one ordinary program, and aeterna-rongroi itself | `process` collector tests, report snapshots |
| `pca-files-present` | Windows 11 with all three PCA files present and readable, their bytes taken from `fixtures/parsers/` | `pca` collector tests, report snapshots |
| `pca-not-present` | Windows with no PCA file at all: a build that predates PCA, or a machine where the service never wrote | `pca` collector tests |
| `pca-access-denied` | Windows 11, the PCA folder present and unreadable, by a process without administrator rights | `pca` collector tests |
| `pca-file-unreadable` | Windows 11 with one PCA file listed and holding no bytes and one that is readable | `pca` collector tests |
| `pca-malformed-lines` | Windows 11 whose launch dictionary has good lines, a line with no delimiter, an impossible date, an empty path and a blank line | `pca` collector tests |
| `pca-utf16-file` | Windows 11 whose launch dictionary is UTF-16 with a byte order mark — not a PCA text file at all | `pca` collector tests |
| `pca-unredactable-path` | Windows 11 whose launch dictionary holds one drive-rooted path, one UNC path and one device path; only the first is a shape SS-mode redaction can reach | `pca` collector tests |
| `prefetch-files-present` | Windows 11 with a readable Prefetch folder holding one `.pf` file, whose bytes are the vendored Windows 10 corpus file, plus the `ReadyBoot` directory and a non-`.pf` file that a real folder also has | `prefetch` collector tests, report snapshots |
| `prefetch-not-present` | Windows with no Prefetch folder at all: Prefetch switched off, or an installation that never had it | `prefetch` collector tests |
| `prefetch-access-denied` | Windows 11, the Prefetch folder present and unlistable, by a process without administrator rights — the expected shape of an ordinary scan (ADR 0015) | `prefetch` collector tests |
| `prefetch-access-denied-elevated` | The same denial with those rights already held, where restarting as administrator would not help | `prefetch` collector tests |
| `prefetch-file-unreadable` | Windows 11 with one `.pf` file listed and holding no bytes and one that is readable | `prefetch` collector tests |
| `prefetch-unsupported-version` | Windows 11 whose Prefetch folder holds one SCCA v26 file from an older Windows, which this parser does not decode | `prefetch` collector tests |
| `prefetch-corrupt-files` | Windows 11 whose Prefetch folder holds an intact `MAM` container over a payload that is not Xpress-Huffman, and the corpus's deliberately bad file | `prefetch` collector tests |
| `registry-bytes-present` | Windows 11, one registry key holding a binary value whose bytes come from `fixtures/parsers/bam/documented-24-byte-value.bin`, one written inline, and one described without bytes — a value that is there and cannot be read | `rongroi-host` fixture tests |
| `bam-entries-present` | Windows 11 whose BAM state holds one account with two executables in it, their value bytes taken from `fixtures/parsers/bam/` | `bam` collector tests, report snapshots |
| `bam-device-paths` | The same with the value name spelled as a device path, the form no SS-mode redaction can reach | `bam` collector tests |
| `bam-two-accounts` | Two accounts with BAM records, so that the report's count of them can be asserted and their SIDs asserted absent | `bam` collector tests |
| `bam-not-present` | A Windows machine with no BAM state at all: the service is not there, or this build never had it | `bam` collector tests |
| `bam-empty` | The BAM key present and holding no account — a machine whose execution history was cleared | `bam` collector tests |
| `bam-access-denied` | Windows 11, the BAM key present and unreadable, by a process without administrator rights | `bam` collector tests |
| `bam-access-denied-elevated` | The same denial with those rights already held, where restarting as administrator would not help | `bam` collector tests |
| `bam-account-denied` | Two accounts, one of whose keys cannot be read, so an unknown number of records is missing | `bam` collector tests |
| `bam-malformed-value` | One account holding a value that decodes, one a byte short of a timestamp, and one that is there and has no bytes | `bam` collector tests |
| `bam-longer-value` | A BAM value longer than the public write-ups describe, as a newer Windows build might write | `bam` collector tests |
| `file-content-present` | Windows 11, one folder holding a file whose bytes are written inline, one whose bytes come from `fixtures/parsers/pca-app-launch/normal.txt`, and one listed without bytes — a file that is there and cannot be read | `rongroi-host` fixture tests |
| `baseline-hardened-win11` | Windows 11 as Microsoft ships it: Secure Boot on, memory integrity configured on, test signing off, TPM 2.0, no FiveM, ordinary programs running | `cargo xtask check-baseline` |
| `baseline-consumer-win11` | Ordinary consumer Windows 11: no memory-integrity policy key at all, FiveM installed with an empty plugin folder | `cargo xtask check-baseline` |

A host named `baseline-*` is read by `cargo xtask check-baseline` and means more than the others: it
asserts that a machine like this is unremarkable, so the whole rule set must stay quiet on it (ADR 0017).
Each one is a written profile; a setting in it is never changed to silence a rule.

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

**One host reaches bytes that carry a real account name**, and it is the only one: the four
`prefetch-*` hosts that point at `fixtures/prefetch/win10-compressed-v30-CMD.EXE-D269B812.pf` inherit
that file's string table, which holds the upstream author's one-letter account name and his machine's
volume serial numbers (`fixtures/prefetch/PROVENANCE.md` records why it was vendored anyway). A
one-letter name cannot be asserted absent — `contains("a")` is true of almost any JSON — so the
`prefetch` collector's tests assert the *shapes* instead: no `\USERS\`, no `VOLUME{`, no
`HARDDISKVOLUME` and no `.DLL` in the serialised observations, and no `loaded_files` or `volumes`
field under any name. The collector emits neither field at all, which is what makes those assertions
meaningful rather than lucky (ADR 0021).

When a fixture is generated from a real Windows install (M2 onwards), record here: what generated it, the
Windows build, that networking was disabled, and who checked it for a real user name, host name or SID, and
how. Neither `tools/fixture-gen/` nor `cargo xtask scrub-check` exists — ADR 0016 counts both among the
promises this repository has made with no code behind them, and `CONVENTIONS.md` §4 records the gap — so
that last check is a person's.
