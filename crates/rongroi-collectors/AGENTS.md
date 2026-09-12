# AGENTS.md — collectors

Adds to the root [`AGENTS.md`](../../AGENTS.md); read that first.

Collectors are the part of this project that reads a player's machine, so the boundary is strictest here.

- **Read-only, always.** Open files, keys and logs for reading only. Never write, delete, rename, lock,
  truncate or change timestamps — not even temporarily, not even "to restore it afterwards".
- **Collect only what a rule needs.** No browser history, screenshots, documents, credentials, tokens or
  unrelated personal files. A new kind of source needs an ADR.
- **No network, no child processes.** Do not shell out to other programs. Restarting the program itself with
  administrator rights (`rongroi_host_windows::elevate`, ADR 0012) is application lifecycle rather than a
  Collector, so it is not an exception to this rule.
- **Environment problems are `Unmeasured`.** Missing rights, a disabled service or an unsupported OS
  produce `CollectorRun::Unmeasured` or a `gaps` entry with a reason — never a panic and never an
  empty "measured" result that would read as "not found".
- **Every collector is tested against `FixtureHost`** for each outcome: found, not found, unmeasured.
- **Out of scope:** code or comments that describe how to hide from, disable, or fool a collector.
  Detection bypasses go to [`SECURITY.md`](../../SECURITY.md) privately.
