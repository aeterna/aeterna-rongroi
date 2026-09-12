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
| `baseline-hardened-win11` | Windows 11 as Microsoft ships it: Secure Boot on, memory integrity configured on, test signing off, TPM 2.0, no FiveM, ordinary programs running | `cargo xtask check-baseline` |
| `baseline-consumer-win11` | Ordinary consumer Windows 11: no memory-integrity policy key at all, FiveM installed with an empty plugin folder | `cargo xtask check-baseline` |

A host named `baseline-*` is read by `cargo xtask check-baseline` and means more than the others: it
asserts that a machine like this is unremarkable, so the whole rule set must stay quiet on it (ADR 0017).
Each one is a written profile; a setting in it is never changed to silence a rule.

The user name `fixtureuser` in these paths is invented; it exists so that SS-mode redaction has something
to replace.

When a fixture is generated from a real Windows install (M2 onwards), record here: the generator script in
`tools/fixture-gen/`, the Windows build, that networking was disabled, and that `cargo xtask scrub-check`
passed.
