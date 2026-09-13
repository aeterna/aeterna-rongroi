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
- **Every collector declares the field names it can emit** (`Collector::fields`). That list is the
  vocabulary a rule's `match` may name and `cargo xtask check-rules` rejects everything outside it, so a
  field emitted and not declared is a correct rule the gate will refuse (ADR 0026). The declaration is
  bound to reality by `every_emitted_field_is_declared` in `src/lib.rs`, which runs every collector over
  every fixture host.
- **Every collector is tested against `FixtureHost`** for each outcome: found, not found, unmeasured.
- **A new collector needs a `baseline-*` host that reads it.** A source no baseline describes makes the
  collector `Unmeasured` there, and `cargo xtask check-baseline` then passes every rule written for it
  whatever it says (ADR 0026).
- **Out of scope:** code or comments that describe how to hide from, disable, or fool a collector.
  Detection bypasses go to [`SECURITY.md`](../../SECURITY.md) privately.
