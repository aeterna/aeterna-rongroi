# ADR 0049 — Which folders SS mode treats as a profile root

- Status: accepted
- Date: 2026-09-15

## Context

SS mode replaces the user-profile part of a path with `%USERPROFILE%` (ADR 0010, AGENTS.md hard rule 5).
Until this ADR, `rongroi_core::view::redact_user_paths` recognised one shape: a drive letter, `:`, `\` or
`/`, the folder `Users` in any ASCII case, the same separator, and the name after it. Every collector that
reports a path — `process`, `pca`, `bam`, `fivem_dir`, `driver_service` — relies on that one function.

ADR 0020, ADR 0021 and ADR 0023 each declined to widen it, for three reasons: it is a change to
`rongroi-core` with its own snapshot churn; it would weaken a function whose precision is testable; and a
wider pattern would still miss a profile folder not named `Users`. Those collectors withhold or refuse a path
that is not drive-rooted instead.

A review of the `driver_service` collector (ADR 0048) found that a drive-rooted path can still name a
profile in shapes the function does not know, so the refusals in each collector do not close the question.
Three shapes were raised, unverified: an 8.3 short name of a profile alias, a spelling of `Users` that only
Windows' own case table folds, and a profile folder moved by the machine's `ProfilesDirectory` setting. The
owner asked that Windows be measured first, and on no one's own PC.

## Measured

A throwaway push-triggered workflow on its own branch, with no pull request, deleted afterwards: run
34964262649, GitHub-hosted image Windows Server 2025 Datacenter, build 26100.33296. Read-only: it tested
whether paths exist and read one registry key. The runner account's name is written `<name>` here.

| Question | Answer on that image |
|---|---|
| 8.3 name creation on `C:` | enabled (volume state 0, the per-volume default) |
| `C:\Documents and Settings` | a junction whose target is `C:\Users` |
| `C:\DOCUME~1\<name>` | resolves |
| `C:\USERS~1` | does not resolve: `Users` is short enough to need no short name |
| `C:\Users\<short name of the account>` | resolves; already redacted, as any name after `Users` is |
| three spellings of `Users` that differ by one non-ASCII letter which looks or case-folds alike | none resolves, as a folder or with `<name>` after it |
| `\\localhost\C$\Users`, `\\127.0.0.1\c$\Users`, `\\?\UNC\localhost\C$\Users` | all resolve |
| `\\?\C:\Users`, `\\.\C:\Users` | resolve; already redacted, because `C:\Users\` is inside them |
| `ProfilesDirectory` under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList` | `C:\Users` |
| `ProfileList` entries | 4: 1 under `ProfilesDirectory`, 3 under `%SystemRoot%` (the service accounts) |

So of the three shapes raised, two are real on current Windows — the short name of `Documents and Settings`
and a moved `ProfilesDirectory` — and the case-table spelling is not. The measurement added one the review
had not raised: the administrative share of a drive, `\\host\X$\Users\<name>`.

## Decision

The owner chose, on 2026-09-15, to widen the profile roots in the core and to read `ProfilesDirectory`.

### 1. The roots the function knows

A profile root is a drive marker, a separator, a root folder and a separator; the name is the segment
after it, and it is replaced together with everything before it back to the drive letter. A separator is one
or more of `\` and `/` in any mix, and a root folder may end in dots or spaces: Windows' path handling reads
each of those spellings as the same folder, and a redactor that required the plain spelling would let the
others past. The collectors that refuse such spellings keep refusing them (ADR 0048); this is so the view
does not depend on every collector doing so.

- **Drive marker**: an ASCII letter followed by `:`, as before; or an ASCII letter followed by `$` whose
  letter comes straight after a separator — the administrative share `\\host\X$\`. The host part stays as
  written; only the drive onwards is replaced.
- **Root folders on any drive**, ASCII case-insensitive: `Users`; `Documents and Settings`; `DOCUME~` followed
  by one or more digits.
- **The machine's own root**, when the report carries one (section 2): its folders after the drive, on its
  own drive letter only.

Everything else is unchanged: a root with no name after it is left alone, `D:\Games\users\z` is left alone
because `users` is not the folder right after the drive, and every occurrence in a string is replaced.

A drive-independent reading of the machine's own root was weighed and not taken: a `ProfilesDirectory` of
`D:\` would then redact the first folder of every path on every drive, `C:\Windows` included, and every row
SS mode lists would lose the part that says where the file is. Bound to its drive, the same value redacts
the first folder of paths on `D:` only, which is the price of the name staying hidden.

### 2. `ProfilesDirectory` in the report header

`scan::run` reads the value, as it reads the boot time before the collectors (ADR 0039). `ReportHeader`
gains `profiles_directory: Option<String>`, additive: `REPORT_SCHEMA_VERSION` stays at 1, it is not
serialised when absent, and a report written before it exists reads back `None`.

- The value is stored as Windows stores it, an expandable string, normally `%SystemDrive%\Users`. A leading
  `%SystemDrive%`, in any ASCII case, is replaced by the `SystemDrive` environment variable when that is a
  drive letter and a colon, the way `driver_service` reads `%SystemRoot%` (ADR 0048). The result is kept only
  when it starts with a drive letter, `:` and a separator and contains no `%`. Anything else — not Windows, the
  value absent, unreadable, of another type, or not expandable this way — is `None`, and SS mode redacts with
  the fixed roots of section 1.
- It is context for the view and nothing else. No rule reads it and no state depends on it (ADR 0002).
- **The Self view carries it** in its header. Neither the text report nor the app prints it: it reads
  `C:\Users` on nearly every machine and says nothing about the evidence. **The SS view drops it**: the
  view needs it to redact and the reviewer does not, and a setting chosen by whoever set up the machine
  could itself carry a name.

Why `None` and not a tagged state like `boot_time`: the only consumer is redaction, and for redaction every
reason there is no value means the same thing — use the fixed roots. A reason would be a field nothing reads.

### 3. What this does not close

A profile can be moved for **one account** by editing that account's `ProfileImagePath` in `ProfileList`,
leaving `ProfilesDirectory` alone. Such a profile is named by no root here. Reading every account's
`ProfileImagePath` into the report was weighed and not taken: it lists the machine's accounts in the header of
every report, which is the kind of listing SS mode exists not to show, and a header that must then itself be
redacted.

This limit is stated in `PRIVACY.md`.

## Alternatives weighed

| Alternative | Why not |
|---|---|
| Keep the function as it was, refuse more shapes per collector | Every collector repeats the refusal and each misses the next shape; the measured short-name form is drive-rooted and passes the check they share |
| Redact any segment after `\Users\` anywhere in a path | Declined in ADR 0020 and ADR 0023, and still misses a moved root; also redacts `D:\Games\users\z` |
| Read every account's `ProfileImagePath` | Lists the machine's accounts in the report header (section 3) |
| Withhold every path not provably outside a profile | "Provably outside" needs the same list of roots; without it every path under a folder the program cannot classify is withheld, and a `found` row would lose the path that makes it checkable |
| Bind the machine's root to any drive | Redacts `C:\Windows\…` when the root is a drive root (section 1) |

## What is unverified

- The measurement is one image. A PC with 8.3 name creation disabled on its system volume has no
  `DOCUME~1`; the root is recognised either way.
- Whether a short name of `Documents and Settings` is ever numbered other than `~1`; the digits are read
  whatever they are.
- Whether a real PC stores `ProfilesDirectory` as `%SystemDrive%\Users` or already expanded; both are read.
- A moved `ProfilesDirectory` was not measured on any machine; the reading of it is tested with fixtures.

## Consequences

- `rongroi_core::view` redacts with the wider roots in evidence and own traces alike; `ReportHeader` gains
  `profiles_directory`; `apps/desktop/src/types.ts` mirrors it.
- ADR 0020, ADR 0021 and ADR 0023 declined a wider redactor; this ADR widens it by named roots, not by
  pattern, and the withholding rules in those collectors stay: a path with no drive letter is still withheld.
- ADR 0048's resolver paragraph points here for what redaction reaches. The resolver's own refusals stay: each
  is still a form this program does not know how to read.
- `PRIVACY.md`, `docs/architecture.md` and CHANGELOG say what SS mode now replaces and what it does not.
