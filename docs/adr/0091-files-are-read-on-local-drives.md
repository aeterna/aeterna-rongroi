# ADR 0091 — Files are read on local drives only

- Status: proposed — the owner chose on 2026-11-01 to treat this as hardening in a normal pull request
- Date: 2026-11-01
- Related: AGENTS.md hard rule 1 (no network) and hard rule 2 (read-only), ADR 0019 (reading file bytes),
  ADR 0030 (the reasons), ADR 0035 (`signature`), ADR 0048 and ADR 0060 (`is_refused_form`), ADR 0079
  (`recorded_files`), ADR 0087 (the drive map and `DriveKind`), ADR 0090 (proposed: the antivirus products
  collector, whose section 3 asks for the same rule)
- Amends: ADR 0048, ADR 0060 and ADR 0079 (a path they resolve is read only when this ADR allows it); ADR 0047
  (`usn_journal::live::open` also opens a link itself with `FILE_READ_ATTRIBUTES`, and `control` also accepts
  the read-only code `FSCTL_GET_REPARSE_POINT`; both stay the only callers `clippy.toml` allows)

## Context

Four collectors open a file at a path that something on the PC wrote: `driver_service` (a service's
`ImagePath`), `autostart` (a `Run` value, a task's action, a service), `recorded_files` (BAM, PCA, the process
list, `UserAssist`) and `fivem_dir` (files under the FiveM folder). They hash it, check its signature, read
its bytes or its `Zone.Identifier` stream, and list its folder to tell a missing file from an unreadable one.

The only checks before the read are the path's shape: `paths::is_drive_rooted` and
`rongroi_host::is_refused_form` (ADR 0048 R1). Neither says where the drive letter leads. A letter can name a
network drive, and a folder on a fixed drive can be a junction, a symbolic link or a mount point whose target
is a share. Windows follows both when `std::fs::File::open`, `WinVerifyTrust` or a directory listing opens the
path, so the read would leave the PC. That breaks hard rule 1 in effect, though no network code is in the
program, and a share that does not answer holds the scan until the collector's budget runs out.

A link that stays on a local drive is ordinary: a moved `Program Files` folder, a game library on
another disk, a profile folder redirected with a junction. Refusing every link would leave such files unhashed,
and a driver placed behind a local junction would get a gap instead of a hash. So a link is followed only as
far as the program can tell, without opening anything through it, that its target is still on a local
drive.

## Decision

### 1. One check, in the host, before every read by path

`rongroi_host::local_read_check(host, path) -> Result<(), NotLocal>` is the only gate. Every host method that
opens a path by name calls it first: `list_dir`, `file_sha256`, `read_file`, `zone_identifier`,
`is_read_only`, `times`, `file_signature` and `file_id`. A refused path returns
`SourceError::NotLocal(NotLocal)` and nothing is opened. Because the check is in the host, a collector cannot
forget it, and a new collector gets it for free.

The check walks the path from the drive down:

1. The path is drive-rooted (`X:\`). A UNC path, a device path (`\\?\`, `\\.\`) or anything else is refused
   as `not_drive_rooted`. The collectors already keep only drive-rooted paths, so this is a backstop.
2. `host.drive_kind(letter)` is `DriveKind::Fixed` or `DriveKind::Removable`. A USB stick is local, and a
   program run from one is exactly what a reviewer wants hashed. `DriveKind::Other` (network, optical, RAM or
   unknown) is refused as `not_local_drive`.
3. For the drive root and each component after it, `host.link_target(prefix)` reports whether that component
   is a reparse point and, if so, what it points at, read from the reparse data itself without following it:
   - not a reparse point: go on to the next component;
   - a junction or mount point, or a symbolic link, whose target is `\??\Y:\…`, or a relative symbolic link
     resolved against its folder: the rest of the path is joined onto the target and the check starts again
     from step 1 for that new path;
   - a target under `\??\UNC\`, or a symbolic link whose target is a UNC path: refused as
     `link_off_local_drive`;
   - a target that is a volume name (`\??\Volume{…}\`) or any other form, or any other reparse tag (OneDrive
     and other cloud placeholders, app execution aliases, and tags this program does not know): refused as
     `link_unsupported`. A cloud placeholder is refused because reading it can make Windows fetch the file.
4. More than eight links on one path is refused as `link_unsupported`.

### 2. Two new host calls

- `drive_kind(letter) -> Result<DriveKind, SourceError>`: on Windows `GetDriveTypeW("X:\")`, the call ADR 0087
  already uses for the drive map.
- `link_target(path) -> Result<Option<LinkTarget>, SourceError>`: on Windows `GetFileAttributesW`, then for a
  reparse point `CreateFileW` with `FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS` and no access
  beyond attributes, and `DeviceIoControl(FSCTL_GET_REPARSE_POINT)`. `LinkTarget` holds the tag kind and, for
  a mount point or symbolic link, the substitute name and whether it is relative. The handle is the link
  itself, never its target.

`FixtureHost` answers both from the fixture: `drive_kind` from `drive_map:` when the fixture models the
letter, otherwise `Fixed`, so fixtures written before this ADR read as they did; `link_target` from a new
`links:` block (`path`, `kind`, `target`), otherwise none. The fixture host runs the same
`local_read_check` before its own reads, so collector tests exercise the gate on any platform.

### 3. What a collector reports

`SourceError::NotLocal` maps to `UnmeasuredReason::NotAttempted` on the fields that read the file
(`sha256`, `signature`, bytes, `Zone.Identifier`): the program chose not to open it, nothing failed. The
observation gains `file_unread` with the `NotLocal` reason (`not_drive_rooted`, `not_local_drive`,
`link_off_local_drive`, `link_unsupported`), so a reviewer sees why the file has no hash. The path itself is
emitted as before, under the same SS-mode redaction. A refused path is never reported as missing: the folder
listing that tells "missing" from "unreadable" is refused the same way.

### 4. What stays unverified

- That `GetFileAttributesW` and `FSCTL_GET_REPARSE_POINT` on a link to a share do not reach the network. They
  read the link's own record on the local volume; a probe on the lab machine with a junction to a share
  confirms it before release.
- That `GetDriveTypeW` on a mapped drive answers without contacting the server.
- A link can be changed between the check and the open. The player controls the PC (ADR 0040); the check
  keeps the program off the network for the paths as they stand during the scan, and claims nothing more.

## Tests

- `local_read_check` on `FixtureHost`: a fixed and a removable drive (allowed); a network letter; a UNC path; a junction
  to a local folder (allowed, read through); a junction to `\??\UNC\…`; a relative symbolic link; a volume-name
  target; a cloud placeholder; nine chained links; an old fixture without `drive_map:` or `links:` (allowed).
- Each of the four collectors: a path on a network letter and a path through a junction to a share get no
  hash, a `not_attempted` gap and the `file_unread` reason; the fixture host fails the test if the file's
  bytes are read. A path through a local junction is hashed as before.
- `drive_service`'s and `autostart`'s missing-file logic: a refused path is not reported missing.
- Windows host: `drive_kind` and `link_target` under the live smoke job, with a junction made in the runner's
  temp folder.

## Consequences

- No file read by path leaves the PC's local drives through a link the program can see.
- Files on optical and RAM drives are no longer read; their rows say `file_unread: not_local_drive`. Files on
  fixed and removable drives, and behind local links, are read as before.
- OneDrive placeholders and app execution aliases are not read. Their rows say so.
- ADR 0090's section 3 can use this check instead of its own.
