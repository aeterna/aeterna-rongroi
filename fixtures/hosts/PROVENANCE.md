# Fixture hosts — provenance

Every host in this folder is **synthetic and hand-written**. None was captured from a real machine, so
none contains a real person's user name, host name, SID or files.

| Host | Describes | Used by |
|---|---|---|
| `secure-boot-on` | Windows 11, Secure Boot reported on | posture collector tests, report snapshots |
| `secure-boot-off` | Windows 11, Secure Boot reported off | posture collector tests, report snapshots |
| `secure-boot-unreported` | Windows 10, Secure Boot state key absent (e.g. legacy BIOS boot) | posture collector tests, report snapshots |
| `registry-access-denied` | Windows 11, Secure Boot key unreadable | posture collector tests |

When a fixture is generated from a real Windows install (M2 onwards), record here: the generator script in
`tools/fixture-gen/`, the Windows build, that networking was disabled, and that `cargo xtask scrub-check`
passed.
