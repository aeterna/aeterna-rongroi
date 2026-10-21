# ADR 0079 — The file a recorded program ran from

- Status: proposed — four owner questions under "Owner decisions"; nothing is built
- Date: 2026-10-21
- Related: ADR 0019 (reading file bytes), ADR 0034 (Prefetch, BAM and PCA carry no identity), ADR 0035
  (signatures), ADR 0044 (gaps for one place), ADR 0048 (refused path forms, R1), ADR 0052 (full scan and
  sensitive kinds), ADR 0064 (`download_host`), ADR 0078 (programs recorded near a game session, step P3)
- Amends: ADR 0078 section 8 (order of reads, I5)

## Context

ADR 0078 section 8 says that a recorded program's file is read, in a full scan, to give the game-windows
view facts I1 to I4. Those facts are whether the file is gone, its signature, whether its name contradicts
its content, and where it lives. P2 shipped the two parsers that read the content:
`rongroi_parsers::content_kind` and `rongroi_parsers::pe_version`. P3 wires them to the collectors. Section
8 left four things to this ADR.

1. **The `Zone.Identifier` stream.** Windows writes this alternate data stream beside a file that a browser
   or another program marked as downloaded. `FilesystemSource` has no method that reads a stream. On
   purpose, `paths::is_refused_form` refuses any path with a `:` after the drive (ADR 0048, R1), so a
   collector cannot reach a stream by spelling its path.
2. **Which records point at a file**, and what each one may emit.
3. **The budget and the order.** Section 8 orders reads by "candidates with more true time facts first".
   That cannot be done in a collector: the time facts are computed in `rongroi-core`'s view, after every
   collector has run.
4. **I5**, the change journal's renames and deletions of the file. The `usn` collector reports counts per
   watched folder and never a file name (ADR 0047). Nothing can answer I5 for an arbitrary path without
   reading names from the journal.

What the code holds on `dev` at `12be663`:

- `FilesystemSource::read_file` reads a whole regular file of at most `MAX_FILE_BYTES` (64 MiB). A larger
  file is `SourceError::TooLarge` and is never truncated (ADR 0019). The Windows host opens it with
  `std::fs::File::open`, for reading only.
- `FilesystemSource::file_sha256` and `file_signature` exist. `fivem_dir`, `driver_service` and
  `autostart` already use them, and `autostart` does so under a 30-second budget of its own
  (`budget_spent`, ADR 0060).
- `bam` emits `disappeared_from_disk` only for a path under Temp, Downloads or a removable drive.
  `process` emits a path when Windows answers, and `pca` emits a path. Prefetch emits only the `.pf` path,
  never the program's path (ADR 0021).
- `SensitiveKind::DownloadHost` exists. SS mode shows it as `%DOWNLOAD_HOST%` unless the player agreed to
  show it (ADR 0052 section 4, ADR 0064).

## Decision

### 1. A method that reads one stream by name, not a path form

`FilesystemSource` gains `zone_identifier(path) -> Result<Option<Vec<u8>>, SourceError>`:

- `path` is the file's own path. The host refuses it, as `is_refused_form` does, when it already holds a
  `:` after the drive or any other refused form. Only after that does the host join the fixed suffix
  `:Zone.Identifier`. A collector never builds a stream path, and no other stream name can be asked for.
- It returns `Ok(None)` when the file or the stream does not exist. It returns at most 64 KiB, as
  `TooLarge` beyond that and never truncated. It opens the stream for reading only, as `read_file` does.
- `FixtureHost` describes a stream as an optional value on a fixture file. `NonWindowsHost` returns
  `Ok(None)`.

The refusal of R1 still stands for every path a collector reads. This method is the one named exception,
and its suffix is a constant in `rongroi-host`.

### 2. A parser for the stream's text

`rongroi_parsers::zone_identifier::parse(&[u8])` reads the INI text: `[ZoneTransfer]`, `ZoneId=`, and
`HostUrl=`. It returns `zone_id` (the number) and `host`: the host of `HostUrl`, lower-cased, with no
scheme, path, query, port or user. `ReferrerUrl`, any other key, and the rest of `HostUrl` are dropped
inside the parser and never reach an observation. The parser takes UTF-8 or UTF-16 with a BOM. It has a
fuzz target, and malformed text is a typed `ParseError`.

### 3. Which records, what they emit

In a full scan, each of `bam`, `pca`, `process` and `autostart` reads the file at a path it already emits
when that path is drive-rooted and not a refused form. `autostart` already hashes and signature-checks;
it adds only the fields marked new. Prefetch is not read: it has no program path until the loaded-file
join of ADR 0078 section 4.

| Field | Kind | From | New? |
|---|---|---|---|
| `file_present` | bool | whether `read_file` found the file | new |
| `sha256` | text | `file_sha256` | new for `bam`, `pca`, `process` |
| `signature`, `signer`, `signer_cert_sha256` | text | `file_signature` (ADR 0035) | new for `bam`, `pca`, `process` |
| `content_kind`, `trailing_data`, `embedded_pe` | text, bool, bool | `content_kind::parse` | new |
| `original_filename` | text | `pe_version::original_filename`, PE kinds only | new |
| `zone_id` | number | `zone_identifier` stream | new |
| `download_host` | text, `SensitiveKind::DownloadHost` | `zone_identifier` stream | new on these collectors |

A field that could not be measured is a gap for that observation only (ADR 0044). A file over 64 MiB is a
`read_failed` gap on `content_kind` and `original_filename`, as every `SourceError::TooLarge` is
(`failure.rs`). Its hash and signature are still checked. A
missing file is `file_present: false`, not a gap. `bam`'s `disappeared_from_disk` is kept as it is,
because a rule reads it.

### 4. Budget and order (amends ADR 0078 section 8)

Each collector reads under its own 30-second budget, as `autostart` does, and says `budget_spent` when the
budget runs out. It reads each distinct path once, newest recorded time first. The newest runs are the
ones nearest the last game session, so this order serves the view without a collector knowing the
sessions. A path the budget did not reach carries no identity fields and is a `budget_spent` gap on them.

### 5. I5 is deferred (amends ADR 0078 section 5)

I5 stays "not known" until an ADR decides whether the `usn` collector may match a file name against a path
it was given, without reporting names. That is a privacy change to ADR 0047 and is not part of this ADR.

### 6. Privacy and SS mode

- Self mode shows every field.
- SS mode shows these fields only through the game-windows view, under ADR 0078 section 9. A candidate with
  an identity fact shows its facts. `download_host` follows `SensitiveKind::DownloadHost`, and `zone_id` is
  shown. `sha256` and `signer_cert_sha256` are shown, as they are for `fivem_dir`.
- `PRIVACY.md` and the full-scan consent text name the reads in the change that ships them: the files that
  Windows' records point at, their download zone and the host they came from.

## Owner decisions (pending)

1. **Budget:** 30 seconds per collector, so up to 90 s more in a full scan (recommended), or 30 seconds
   shared by the three collectors.
2. **Order:** newest recorded time first, per collector (recommended), or path order.
3. **I5 deferred** to its own ADR on the change journal (recommended), or I5 dropped from ADR 0078.
4. **`download_host` in SS mode** under the existing website question of ADR 0052 (recommended), or never
   shown in SS mode.

## Alternatives weighed

| Alternative | Why not |
|---|---|
| Let a collector pass `path:Zone.Identifier` to `read_file` | Undoes R1 for every collector. Any stream name could then be read. |
| List every stream of a file (`FindFirstStreamW`) | A new API and a new privacy question. Streams other than `Zone.Identifier` carry application data. |
| Keep the whole `HostUrl` | A URL can carry a user name, a token or a file name. The host is enough to say where a file came from. |
| Read `ReferrerUrl` | It names the page the person was reading, which is browsing history. |
| One shared cache of reads across collectors | Collectors run independently today, and a shared cache would be new shared state between them. The same path read twice costs one more read, and the budget bounds that. |

## What is unverified

- Whether opening `Zone.Identifier` for reading changes the file's last-access time on Windows 11 with the
  default `NtfsDisableLastAccessUpdate` setting. To be measured on a Windows PC before code is merged, the
  way ADR 0037 measured its read.
- How many distinct paths `bam`, `pca` and `process` hold on an ordinary PC, and how many of them 30
  seconds reaches. To be measured in P3's first real-Windows run.
- Whether every browser in common use still writes `HostUrl` (Chromium-based browsers and Firefox have
  written it; not checked for this ADR).

## Consequences

- `rongroi-host`: `FilesystemSource::zone_identifier`, the suffix constant, and the fixture form.
- `rongroi-host-windows`: its implementation, with the refused-form check before the suffix.
- `rongroi-parsers`: `zone_identifier::parse` and a fuzz target.
- `rongroi-collectors`: the fields in section 3 on `bam`, `pca`, `process` and `autostart`, full scan
  only, with budgets.
- `rongroi-core`: the game-windows view fills I1 to I4 from these fields; I5 stays "not known".
- `PRIVACY.md`, the consent text and `docs/architecture.md` change with the code.
