# ADR 0022 — Enumerating registry keys and reading a value's bytes

- Status: proposed
- Date: 2026-09-12

## Context

ADR 0019 gave a host a way to hand a collector the bytes of a file, and that unlocked three of the four
parsers in `rongroi-parsers`: PCA (ADR 0020) and Prefetch (ADR 0021) are wired, and the Event Log is
waiting on the hang recorded in `docs/testing.md`. The fourth reads no file at all.

BAM is a registry artifact, and an unusual one. `HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings`
holds one subkey per user account, and inside each subkey **the name of every value is an executable's
path and the data of every value is the artifact** (`rongroi_parsers::bam`). Reading it therefore needs
three things `RegistrySource` does not have:

- the subkeys of a key, because the account subkeys are not known in advance;
- the value names of a key, because the paths are not known in advance either — and here the *name* is
  half the artifact;
- a value's raw bytes, because `rongroi_parsers::bam::parse_value` takes `&[u8]` and `RegistrySource`
  offers only `read_u32` and `read_string`.

ADR 0019 says as much in one line: "The fourth, BAM, needs registry enumeration and a binary registry
value, which is a separate decision." This is that decision, and it is deliberately the same shape as
ADR 0019's, because the two capabilities are answering the same question one source apart.

## Decision

### Three methods on `RegistrySource`, not a new trait

The same argument ADR 0019 made for putting `read_file` on `FilesystemSource`. This codebase splits
source traits by **which source is touched** — the registry, the file system, the environment, the
kernel, the TPM, the process list — and never by which operation is performed on one of them.
`subkeys`, `value_names` and `read_bytes` touch the registry and nothing else, open the same keys
`read_u32` already opens, and need the same permission. A `RegistryEnumerationSource` would be the
second trait split *within* one source and a seventh supertrait every implementor has to carry anyway.

`value_names` returns names and never data, which is what keeps every byte that reaches a parser going
through `read_bytes` and its limit. The alternative — one method returning name and bytes together, as
the underlying `windows-registry` iterator does — would read a key's whole contents in one call with
the limit applied to nothing.

### `Ok(None)` is a key that is not there; an empty list is a key with nothing in it

The distinction `list_dir` makes for a directory (ADR 0009) and `read_file` makes for a file
(ADR 0019). "There is no BAM key on this machine" is something the collector looked at and saw, and it
is the ordinary state of a Windows build that has no BAM, while "the key is there and holds no account"
is a different statement and is the one that would matter to a reviewer. `read_bytes` reports an absent
key or an absent value as `Ok(None)`, which is what `read_u32` and `read_string` already do.

A value of a type other than `REG_BINARY` is an error, not an answer. A caller that wanted a number or
a string has a method for it; converting here would hand a parser bytes that mean something else, and
neither the fixture host nor `windows-registry` would be telling the caller it had happened.

### Every read of a value's bytes is bounded, at 64 KiB

Same reason as ADR 0019: the value is on the machine being examined, so its size is chosen by whoever
put it there, and this program reads dishonest machines by design. Exceeding the bound is
`SourceError::TooLarge { limit }` — the variant ADR 0019 added, reused rather than duplicated — and
nothing is truncated, because a truncated artifact parses as a damaged one and the report would then
describe damage this program caused.

Why 64 KiB:

- The artifact is 24 bytes. The layout `rongroi_parsers::bam` documents is a `FILETIME`, a DWORD and
  twelve bytes with no established meaning, so the limit is some 2 700 times the whole value, which
  leaves room for a Windows build that writes a longer one — the parser already accepts any length of
  at least eight bytes for exactly that reason (ADR 0013).
- It is a thousandth of the 64 MiB a file may be, and that ratio is the difference between the two
  sources: the registry is a settings store and a value in it is small by design, while a file is
  where Windows puts things that are not.
- It is far below a size whose refusal costs a player's machine anything.

**The bound is honest about what it bounds.** `rongroi_host::bound_registry_value` takes bytes rather
than a reader, because a platform registry API hands back a whole value in one call: `windows-registry`
asks the registry how long the value is and allocates that much before this program sees any of it. So
the limit bounds what crosses the trait boundary and what a parser is handed — not the allocation the
platform already made. `read_bounded` can bound both because it owns the reading loop; this cannot, and
saying so here is better than a limit that reads like a guarantee it does not give. The same is true of
`value_names`: `windows-registry`'s value iterator allocates the largest value in the key once, up
front. See "What is unverified".

### The number of subkeys and of values is *not* bounded

Considered and declined. `list_dir` does not bound a directory listing either, and the reason is the
one `rongroi_host_windows::filesystem` already states for failing a whole listing rather than returning
part of it: "a partial list that looked complete would be read as 'nothing else was there'". A
truncated enumeration is the one answer that is actively wrong, because the thing a reviewer reads out
of this collector is which programs are recorded and how many.

What makes that safe to leave unbounded is that the per-item cost is bounded by the registry itself and
is small: a subkey name and a value name are strings, and this program keeps one `String` per name and
reads the values one at a time rather than holding them all. A key with a million subkeys costs a list
of a million short strings, which is a different order of magnitude from a single value declaring
itself gigabytes long — the case the byte limit exists for. If a real machine ever shows an enumeration
large enough to matter, the honest answer is to record the size, not to silently stop reading.

### A fixture writes a binary value where it already writes a value

`RegistryValue` is an untagged enum of `Dword(u32)` and `Text(String)`; it gains `Binary`, written as a
map with the `content:` / `from:` pair ADR 0019 gave a file entry:

```yaml
registry:
  'HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-…-1001':
    'C:\Users\fixtureuser\Downloads\example.exe':
      from: '../../parsers/bam/documented-24-byte-value.bin'
```

A number, a string and a map cannot be mistaken for one another, which is what makes an untagged enum
safe to extend here. `from:` is resolved when the host is loaded, so a path that does not resolve fails
as a broken fixture rather than looking like a value whose bytes cannot be read, and `from_yaml_str`
refuses it for want of a directory — all exactly as for a file. A value written with neither describes
a value that is there and cannot be read, which is the per-value failure an entry without `content:`
already models on the file side.

Two smaller decisions follow from BAM's shape:

- **The fixture now keeps the spelling it was given** for a key path and a value name, beside the
  lower-cased form its lookups are keyed by. Enumeration hands back the spelling. Before this change
  nothing enumerated, so lower-casing was invisible; a collector that emits a value name would
  otherwise report a path the machine does not have.
- **Subkeys are found by scanning for keys underneath the one asked for**, because a fixture describes
  a key by writing its values. A key that only has subkeys — `…\UserSettings` itself — is therefore
  there and holds no value, rather than not existing.

A fixture that describes no `registry:` block at all still answers "not there" rather than
`Unsupported`. That is what `read_u32` has always done, and it is what keeps every fixture written
before this change loading unchanged and every rule quiet on the two baselines.

### Alternatives weighed

| Alternative | Why not |
|---|---|
| A new `RegistryEnumerationSource` trait | Splits one source by operation, which is not the axis this codebase splits on (ADR 0019) |
| One `values()` returning names *and* data | The underlying iterator's shape, not this program's: it reads a key's whole contents in one call and leaves the byte limit with nothing to apply to |
| `read_bytes` accepting any value type and converting | A `REG_DWORD` read as bytes is four bytes that mean a number. The caller asked for an artifact, and nothing would tell it that it got something else |
| A `bytes: 'A0A1…'` hex string on the value | A second spelling for bytes that a fixture already has two of. `from:` also keeps the artifact corpora the single copy, which is what ADR 0019 wanted |
| Bounding the number of subkeys or values | A partial enumeration reads as "there was nothing else", which is the only wrong answer available here |
| Reading a value's length first and refusing before allocating | `windows-registry` exposes that only through an `unsafe` call taking a `PCWSTR` this crate cannot build safely. It would buy a bound on the platform's own allocation at the cost of new `unsafe` in exchange for a case no real BAM value reaches — recorded as unverified rather than taken |
| No limit, since a registry value is small | "A registry value is small" is a statement about honest machines |

## What is unverified

**The live implementation was not run.** `LiveHost::subkeys`, `value_names` and `read_bytes` are
compiled and linted for `x86_64-pc-windows-msvc` from macOS and are exercised by the Windows CI job as
every other live implementation is; nothing here executed them. Specifically unexercised: that opening a
key Windows denies yields `ERROR_ACCESS_DENIED` and therefore `SourceError::AccessDenied` rather than
some other code, and that `RegEnumKeyExW` behaves as `windows-registry`'s iterator assumes on a key
whose subkeys change while it is being read.

**The allocation inside `windows-registry` is not bounded by anything this program controls, and no
machine was measured for it.** `Key::get_bytes` asks the registry for the value's length and allocates
it; `Key::values` allocates the largest value in the key once. A hostile machine can therefore make
this program allocate more than 64 KiB before the limit is applied, and how much more is whatever
Windows will store in one value — a number this repository has not established. The thing to check on a
real machine is what `RegQueryInfoKeyW` reports for a key holding a deliberately large value, and
whether refusing it earlier is worth the `unsafe` it would take.

**Registry element size limits were not verified.** Public guidance that a value above a couple of
kilobytes belongs in a file, and that a "standard format" value is capped near 1 MB, is not something
this pull request checked against a Windows machine or a current Microsoft document. The 64 KiB limit
is reasoned from the artifact's own 24 bytes and from ADR 0019's file limit, both of which are in this
repository, and not from those figures.

**Which permission the BAM key needs is not established here.** Nothing in this repository states that
reading `…\Services\bam\State` requires an elevated token — unlike Prefetch (ADR 0015) and the Event
Log (ADR 0018), whose ADRs say so for their artifacts. This capability is indifferent to the answer: it
attempts the read and reports `AccessDenied` when Windows refuses. The collector that uses it (ADR 0023)
records the same gap.

## Consequences

- `RegistrySource` gains three methods; `LiveHost`, `NonWindowsHost` and `FixtureHost` implement them.
  All three are in-repo and `publish = false`, so nothing downstream breaks. `Host` gains no supertrait.
- `SourceError` gains nothing: `TooLarge` already exists and already means this.
- No dependency is added and `Cargo.lock` does not move. `Key::keys`, `Key::values` and `Key::get_bytes`
  are already in the `windows-registry` 0.100 the workspace pins, no new `windows` feature is needed,
  and no `unsafe` is written.
- No collector, no rule and no report field changes in this pull request's first commit, so no snapshot
  moves and `check-baseline` is untouched.
- `fixtures/hosts/registry-bytes-present` is the first fixture host to point a registry value at a file
  in another fixture directory. It references `fixtures/parsers/bam/` and copies nothing, which is the
  rule ADR 0019 set for the corpora.
- **What is still deliberately not read.** This adds the subkeys of a key a collector names, the value
  names of a key it names, and the bytes of a binary value it names. It does not add recursion, a key's
  last-write time, its security descriptor, its class, the number of values as a datum of its own, or
  any hive other than `HKLM` — `LiveHost` still refuses every other root. Everything is opened for
  reading; nothing on the scanned machine is written (AGENTS.md hard rule 2).
