# ADR 0009 — File system and environment sources

- Status: accepted
- Date: 2026-09-12

## Context

Until now a collector could read one thing: the registry. The first artefact that is not a registry value
is FiveM's own plugin folder, `%LOCALAPPDATA%\FiveM\FiveM.app\plugins`, whose contents FiveM loads at
start-up. Reading it needs two things the `Host` trait did not offer: a directory listing and the value of
an environment variable. Adding a new kind of source is an ADR (CONVENTIONS.md §8).

The path was confirmed on a Windows 11 machine on 2026-09-12: that folder exists, `%APPDATA%\CitizenFX`
exists, and `C:\Program Files\FiveM` does not.

## Decision

**Two traits, not one.** `Host` now requires `RegistrySource + FilesystemSource + EnvironmentSource`.
`FilesystemSource` has `list_dir` and `file_sha256`; `EnvironmentSource` has `env_var`. They are separate
because a collector that only expands a variable should not have to be given the file system, and because
`FixtureHost` can then describe either one alone.

**`list_dir` returns `Option`.** `Ok(None)` means the directory does not exist, and that is a different
statement from an error. A player without FiveM must produce `Measured` with no observations — which the
engine turns into `NotFound`, the honest answer — and not `Unmeasured`, which would claim the tool could
not look. An error is reserved for a folder that is there but could not be read.

**A per-item failure omits a field; it is never a `gap`.** `gaps` is per field for the whole run: it tells
the engine "no rule may read this field as *not found*, because it was never read". One file whose hash
cannot be read says nothing about the other files, so that observation is emitted with `path` and
`location` and without `sha256`. The file is never dropped and a hash is never invented. A folder that
could not be listed at all is the opposite case: every field is then a gap.

**Hashes are streamed and well-formed.** `sha256_file` reads a file in blocks rather than into memory, so
a large plugin costs a buffer rather than its own size. It lives in `rongroi-host` next to the trait, not
in `rongroi-host-windows`, so that every implementation produces the same digest in the same form and so
that the loop is covered by tests that need no Windows. A rule's `allow` compares the `sha256` field
literally, so the collector emits it only as 64 lowercase hex characters, or not at all.

**What is deliberately not read.** Only the names of the entries directly inside the folder, whether each
is a file, and the hash of each file. No timestamps, no size, no owner or ACL, no attributes, no
recursion into subdirectories, and no content beyond what the digest consumes. Subdirectories are listed
so they can be excluded, and are not observed. Everything is opened for reading; nothing on the scanned
machine is written, renamed, locked or touched.

**Amended by ADR 0019.** "No content beyond what the digest consumes" described a file-system source
whose only reason to open a file was to hash it. `FilesystemSource::read_file` returns the bytes of a
file a collector names, bounded at 64 MiB, because three of the four parsers need bytes and nothing on
`Host` supplied them. The rest of the paragraph above stands: still no recursion, no timestamps, no size,
no owner or ACL, no attributes, and nothing read that a collector did not name.

**No rule reads this collector yet.** A rule that says "there is a file in FiveM's plugin folder" matches
ordinary overlay software on a great many legitimate machines, and neither an allow-list of known-good
hashes nor Authenticode signer checking exists yet — and `allow` may only identify software by `sha256` or
`signer`, never by file name. Shipping the rule now would produce evidence that a reviewer could not act
on. The rule follows once signer checking or a starter allow-list exists.

**Signer checking exists since ADR 0035**, which also changes what `allow` compares — the signing
certificate's SHA-256, never the signer's name — and extends this collector to FiveM for GTA V Enhanced's
`asi` folder under `%APPDATA%`. The rule itself is still to be written.

This ADR originally continued: *"The observations are still visible in Self mode, where a person reads
them."* That was false when it was written. A `Report` held one `Evidence` per rule, and an
observation reached it only inside `EvidenceState::Found`, so a collector with no rule produced
nothing any screen could show and everything this one read was discarded. ADR 0014 makes the sentence
true: an observation that no rule matched is kept as an **unmatched observation**, listed in Self mode
and counted — never listed — in SS mode.

## Consequences

- `FixtureHost` gains `env:` and `filesystem:` blocks; both default, so the fixtures written before this
  change still load, and the unknown-field check still rejects what it rejected before.
- `NonWindowsHost` reports `Unsupported` for the file system and `None` for every variable, so the
  collector is `Unmeasured { not_windows }` off Windows.
- `%LOCALAPPDATA%` being unset makes the collector `Unmeasured { read_failed }`: there is no folder to
  look in, so nothing was looked at.
- The live implementation needs no Windows API and no `unsafe`; `std::fs` is enough. It is type-checked
  and linted for `x86_64-pc-windows-msvc` from any operating system and exercised by the Windows CI job.
- The hash helper duplicates, in a small way, `rongroi_core::provenance::sha256_hex`. The two crates do
  not depend on each other, and this one streams rather than taking a slice.
- A path is now part of an observation, so SS-mode redaction (`rongroi_core::view`) matters for this
  collector's output the moment a rule starts reading it.
