# ADR 0079 — The file a recorded program ran from

- Status: accepted — the owner decided the five questions below on 2026-10-21, each as recommended;
  nothing is built
- Date: 2026-10-21
- Related: ADR 0019 (reading file bytes), ADR 0034 (Prefetch, BAM and PCA carry no identity), ADR 0035
  (signatures), ADR 0044 (gaps for one place), ADR 0048 (refused path forms, R1), ADR 0052 (full scan and
  sensitive kinds), ADR 0064 (`download_host`), ADR 0078 (programs recorded near a game session, step P3)
- Amends: ADR 0078 sections 5 (I5) and 8 (order of reads)

## Context

ADR 0078 section 8 says that a recorded program's file is read, in a full scan, to give the game-windows
view facts I1 to I4. Those facts are whether the file is gone, its signature, whether its name contradicts
its content, and where it lives. P2 shipped the two parsers that read the content:
`rongroi_parsers::content_kind` and `rongroi_parsers::pe_version`. Both take the whole file, not its first
and last bytes (ADR 0078, "As built: P2"). P3 wires them to the collectors. Section 8 left four things to
this ADR.

1. **The `Zone.Identifier` stream.** Windows writes this alternate data stream beside a file that a browser
   or another program marked as downloaded. `FilesystemSource` has no method that reads a stream. On
   purpose, `paths::is_refused_form` in `rongroi-collectors` refuses any path with a `:` after the drive
   (ADR 0048, R1), so a collector cannot reach a stream by spelling its path.
2. **Which records point at a file**, and what each one may emit.
3. **The budget and the order.** Section 8 orders reads by "candidates with more true time facts first".
   That cannot be done in a collector: the time facts are computed in `rongroi-core`'s view, after every
   collector has run.
4. **I5**, the change journal's renames and deletions of the file. The `usn` collector reports counts per
   watched folder and never a file name (ADR 0047). Nothing can answer I5 for an arbitrary path without
   reading names from the journal.

What the code holds on `dev` at `12be663`:

- `FilesystemSource::read_file` reads a whole regular file of at most `MAX_FILE_BYTES` (64 MiB). A larger
  file is `SourceError::TooLarge` and is never truncated (ADR 0019). The Windows host opens the file with
  `std::fs::File::open`, for reading only. `NonWindowsHost` answers every file method with
  `SourceError::Unsupported`.
- `file_sha256` and `file_signature` exist. `fivem_dir`, `driver_service` and `autostart` already use them;
  `autostart` does so under a 30-second budget of its own, checked between files (`budget_spent`, ADR
  0060).
- Gaps are per run, or per place for a collector that declares a discriminator (ADR 0044). `bam`, `pca`
  and `process` declare none, so a gap there covers every observation of the run.
- `bam` emits `disappeared_from_disk` for a path it treats as ephemeral: under Temp, Downloads,
  `\removable\`, `\usb\` or `\media\`, or on a drive other than the system drive. When the host cannot
  answer, it falls back to `std::path::Path::exists` inside the collector, outside the `Host` trait.
  `process` emits any non-empty image path, and `pca` emits a path. Prefetch emits only the `.pf` path,
  never the program's path (ADR 0021).
- `SensitiveKind::DownloadHost` exists with its own SS-mode question, default no. Until the player answers
  yes, SS mode shows `%DOWNLOAD_HOST%`. A host that is an address is reported as its kind only (ADR 0064
  section 4, ADR 0052 section 4).

## Decision

### 1. A method that reads one stream by name, not a path form

- `is_refused_form` moves from `rongroi-collectors` to `rongroi-host`. Collectors keep calling it from its
  new place, and the host can now call it too.
- `FilesystemSource` gains `zone_identifier(path) -> Result<Option<Vec<u8>>, SourceError>`. `path` is the
  file's own path. The host refuses it with `SourceError::Failed` when `is_refused_form` refuses it, or
  when it already holds a `:` after the drive. Only then does it join the fixed suffix
  `:Zone.Identifier`, a constant in `rongroi-host`. A collector never builds a stream path, and no other
  stream name can be asked for.
- `Ok(None)` means the file or the stream does not exist. The stream is read only up to 64 KiB; beyond
  that it is `TooLarge` and never truncated. `FixtureHost` describes a stream as an optional value on a
  fixture file. `NonWindowsHost` answers `Unsupported`, as for every other file method.
- **Precondition:** the method is not merged before a measurement on a Windows 11 PC shows that opening
  the stream for reading leaves the file's and the stream's times as they were. ADR 0037 measured its own
  read the same way. Until then the collectors read everything in section 3 except the stream.

### 2. A parser for the stream's text

`rongroi_parsers::zone_identifier::parse(&[u8])` reads the INI text: `[ZoneTransfer]`, `ZoneId=`, and
`HostUrl=`. It returns `zone_id` (the number) and the host of `HostUrl`, handled as ADR 0064 section 4
handles `download_host`: a name is lower-cased and kept with no scheme, user, password, port, path or
query, and an address is reported only as its kind. `ReferrerUrl`, any other key, and the rest of
`HostUrl` are dropped inside the parser and never reach an observation. It reads UTF-8, or UTF-16 with a
BOM. It has a fuzz target, and malformed text is a typed `ParseError`.

### 3. Which records, what they emit

In a full scan, each of `bam`, `pca`, `process` and `autostart` reads the file at a path it emits, when
that path is drive-rooted. For `process` this is a new condition: today it emits any non-empty path.
Prefetch is not read, because it has no program path until P3's later loaded-file join (ADR 0078
section 4).

Every observation with such a path carries **`identity_read`**, which says what happened to the read:

| `identity_read` | Meaning | Identity fields present |
|---|---|---|
| `read` | the file was read | all that apply |
| `missing` | the file does not exist (`read_file` returned `Ok(None)`) | none; I1 is true |
| `too_large` | over 64 MiB | `sha256`, signature fields; not `content_kind`, `original_filename` |
| `access_denied`, `failed` | the read failed, worded as `failure::read_failure` words it | none |
| `refused_form` | the path is a form `is_refused_form` refuses | none |
| `budget_spent` | the collector's budget ran out before this path | none |
| (absent) | a standard scan, or a path that is not drive-rooted | none |

This replaces a gap: a gap covers the whole run in these collectors (ADR 0044), and one unreadable file
must not hide the others.

| Field | Kind | From | Collectors |
|---|---|---|---|
| `identity_read` | text | above | `bam`, `pca`, `process`, `autostart` |
| `sha256`, `signature`, `signer`, `signer_cert_sha256` | as ADR 0035 | `file_sha256`, `file_signature` | `bam`, `pca`, `process` (`autostart` has them already) |
| `content_kind`, `trailing_data`, `embedded_pe` | text, bool, bool | `content_kind::parse` | all four |
| `original_filename` | text | `pe_version::original_filename`, PE kinds only | all four |
| `zone_id` | number | the stream, after the section 1 precondition | all four |
| `download_host` | text, `SensitiveKind::DownloadHost` | the stream | all four |

When several observations of one collector share a path, the file is read once and each observation
carries the same fields. `bam`'s `disappeared_from_disk` stays as it is, because a rule reads it. Its
fallback to `std::path::Path::exists` is replaced by the host's answer in the same change, so the collector
makes no OS call of its own.

### 4. Budget and order (amends ADR 0078 section 8)

Each collector reads under its own 30-second budget, checked between files as `autostart` does. Paths are
read in order of distance from the collector's own newest record of a FiveM or GTA V program, nearest
first, so that the runs just before and just after the last game come first. A collector with no such
record reads newest first.

### 5. I5 is deferred (amends ADR 0078 section 5)

I5 stays "not known" until an ADR decides whether the `usn` collector may match a file name against a path
it was given, without reporting names. That is a privacy change to ADR 0047 and is not part of this ADR.

### 6. Privacy and SS mode

- Self mode shows every field. A saved record (ADR 0073) holds exactly what the SS screen showed, so it
  carries these fields only where the SS rules below allow. This corrects ADR 0078 section 8, which said
  they reach a saved report as observation fields.
- SS mode shows these fields only through the game-windows view, for a candidate with an identity fact
  (ADR 0078 section 9). There, `identity_read`, `content_kind`, `trailing_data`, `embedded_pe`,
  `original_filename`, `zone_id`, `signature`, `sha256` and `signer_cert_sha256` are shown, and `signer` is
  shown as `fivem_dir` shows it today. `download_host` follows `SensitiveKind::DownloadHost`.
- The identity fields are added to `SS_WITHHELD_FIELDS` for `bam`, `pca` and `process`. A rule match can
  therefore never put them in SS mode by another route.
- `PRIVACY.md` and the full-scan consent text name the reads in the change that ships them: the files that
  Windows' records point at, their signature and content kind, their download zone, and the host they came
  from.

## Owner decisions (2026-10-21, each as recommended)

1. **Budget:** 30 seconds per collector, so up to 90 s more in a full scan.
2. **Order:** nearest to the collector's newest FiveM/GTA V record first.
3. **I5 deferred** to its own ADR on the change journal.
4. **`download_host` in SS mode** under ADR 0064's existing question.
5. **The stream measurement** (section 1 precondition) on the owner's Windows 11 PC before the stream
   method merges.

## Alternatives weighed

| Alternative | Why not |
|---|---|
| Let a collector pass `path:Zone.Identifier` to `read_file` | Undoes R1 for every collector. Any stream name could then be read. |
| Per-observation gaps for an unreadable file | No discriminator in these collectors, so a gap covers the whole run (ADR 0044). `identity_read` says the same thing per observation. |
| List every stream of a file (`FindFirstStreamW`) | A new API and a new privacy question. Streams other than `Zone.Identifier` carry application data. |
| Keep the whole `HostUrl` | A URL can carry a user name, a token or a file name. The host is enough to say where a file came from. |
| Read `ReferrerUrl` | It names the page the person was reading, which is browsing history. |
| One shared cache of reads across collectors | Collectors run independently today, and a shared cache would be new shared state between them. The same path read twice costs one more read, and the budgets bound that. |

## What is unverified

- Whether opening `Zone.Identifier` for reading changes a time on Windows 11 with the default
  `NtfsDisableLastAccessUpdate` setting. This is the section 1 precondition.
- How many distinct paths `bam`, `pca` and `process` hold on an ordinary PC, and how many of them 30
  seconds reaches. To be measured in P3's first real-Windows run.
- Whether every browser in common use still writes `HostUrl`. Chromium-based browsers and Firefox have
  written it; this was not checked for this ADR.

## Consequences

- `rongroi-host`: `is_refused_form` moves here; `FilesystemSource::zone_identifier`, the suffix constant,
  and the fixture form.
- `rongroi-host-windows`: the implementation, refusing before joining the suffix.
- `rongroi-parsers`: `zone_identifier::parse` and a fuzz target.
- `rongroi-collectors`: `identity_read` and the fields in section 3 on `bam`, `pca`, `process` and
  `autostart`, full scan only, with budgets; `bam`'s presence check goes through the host.
- `rongroi-core`: `SS_WITHHELD_FIELDS` grows. The game-windows view fills I1 to I4 from these fields, and
  I5 stays "not known".
- `PRIVACY.md`, the consent text and `docs/architecture.md` change with the code.
