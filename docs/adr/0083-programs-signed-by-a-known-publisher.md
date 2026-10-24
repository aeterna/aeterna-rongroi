# ADR 0083 — Programs signed by a known publisher

- Status: accepted — the owner decided the five questions below on 2026-10-24, each as recommended, and
  approved the text as drafted; nothing is built
- Date: 2026-10-24
- Related: ADR 0035 (offline signature checking; a signer's name is not an identity), ADR 0036 (certificate
  pins and their expiry), ADR 0061 section 4 (no ranking), ADR 0078 (programs recorded near a game session,
  section 5, fact O1, and step "O1"), ADR 0079 (the file a recorded program ran from, sections 3 and 6)
- Amends: ADR 0078 section 5 (where O1's certificates come from, and when O1 folds a candidate)

## Context

ADR 0078 section 5 defines one "quiet" fact: **O1**, "a valid signature whose certificate is in
`rules/certificate-pins.csv`", and says that candidates with O1 are folded into one line, "N programs
signed by a known publisher", which opens to the list. The owner left O1 out of P6 and put it after P6b,
which brings the signer (ADR 0078, P6 decision 2).

What the code holds today (`dev` at `b478ccc`):

- Each candidate carries `file`, what `recorded_files` read at its path in a full scan (ADR 0079 section 3,
  ADR 0078 P6b): `signature` (`valid`, `invalid`, `no_embedded_signature`, `unverifiable_offline`),
  `signer` and `signer_cert_sha256`.
- `rules/certificate-pins.csv` holds **one row**: Rockstar Games' certificate, which one rule's `allow`
  names to check `FiveM.exe` (ADR 0035, ADR 0036). Its purpose is to tell a rule's author when an `allow`
  entry goes stale. It is read by `cargo xtask check-rules` and `check-pin-expiry`, never by the core.
- `FiveM.exe`, `GTA5.exe`, `GTA5_Enhanced.exe`, `PlayGTAV.exe` and the game process are not candidates
  (`game::is_timeline_name`, `session::anchor_name`).

Read literally, O1 therefore folds nothing: the one pinned certificate signs programs that are never
candidates. A useful O1 needs a list of the certificates of the ordinary programs a gaming PC runs near a
session (chat, launchers, recording and GPU tools, a browser), which no file in this repository holds.

Two things about such a list are known without measuring:

- **A certificate, not a name.** ADR 0035 explains why a signer's name is not an identity: anyone can buy a
  certificate whose subject resembles a publisher's. Only the certificate's SHA-256 identifies it.
- **Certificates leak.** A publisher's private key has leaked before, and cheats and malware have been
  signed with leaked certificates. A list entry is a claim about who holds a key, and folding hides a
  program from the first read of the list.

How many candidates an ordinary evening produces, and how many of them a list would fold, is not measured.
That is step P7's baseline (ADR 0078, "Order of work").

## Decision

### 1. A list of its own: `rules/known-publishers.csv`

One row per certificate: `signer_cert_sha256`, `subject`, `product` (the program it was measured from, as
the publisher names it), `not_before`, `not_after`, `measured_on`, and `source` (the released file and its
version). It follows the same rule as the pins: a row is a measurement from a file the publisher released,
never from memory, and a renewed certificate adds a row beside the old one.

- It is built into the rules bundle, so the core reads it. Today the bundle carries only `rule.yaml` files
  and the CSV files beside them (`source_tree::data_beside`), and `RawBundle` has no place for a list at the
  root of `rules/`, which is why `certificate-pins.csv` never reaches the core. This change adds that place:
  one field on the bundle, and one entry in the source-tree walk. The bundle's hash changes when a row
  changes.
- `cargo xtask check-rules` checks it on every pull request: 64 lowercase hex characters, no repeated
  certificate, no empty field, dates that parse.
- `rules/certificate-pins.csv` stays as it is, for rules only. The two lists answer different questions:
  "is this rule's `allow` still current?" and "may the view fold this program?".

### 2. When O1 holds, and when it folds

O1 holds for a candidate when `file.read` is `read` or `too_large`, `file.signature` is `valid`, and
`file.signer_cert_sha256` is a row of the list.

O1 **folds** a candidate only when, as well, none of I1, I3, I4 and L1 is true. (I2 is false whenever O1
holds.) A file signed with a known certificate that ran from Downloads, or whose name contradicts what it
is, stays in the list where its facts put it, and O1 is shown on it as one more line. A leaked certificate
therefore never hides a file that has another fact about it.

### 3. What the reader sees

- In Self mode, folded candidates leave the ordered list and come last, under one line, "N programs signed
  by a known publisher" (ADR 0078 section 5), with a note that being folded says nothing on its own.
- The desktop app shows that line as a closed `<details>`; opening it shows each folded candidate's card,
  as an unfolded one is shown. The CLI prints the line, then the folded candidates' cards under it.
- Folding changes no count: each folded candidate still counts in its windows.

### 4. SS mode

A folded candidate has no identity fact, so SS mode never names it (ADR 0078 section 9). It is dropped
before the view is shown, as now, and stays in the per-window counts of programs SS mode does not name.
SS mode therefore shows no folded line and no folded card. Section 3 is Self mode only. O1 changes nothing
in SS mode, and neither the consent text nor `PRIVACY.md` changes. A candidate SS mode does name has an
identity fact, so it is never folded, and in SS mode it shows O1 as one of its lines, like any other fact.

### 5. The first rows

A read-only probe on the owner's Windows 11 PC lists the signer certificate of each program BAM, PCA and
UserAssist record there, grouped by certificate, with its subject and how many programs it signs. The
owner chooses which publishers enter the list from that table, and each row cites the file it was measured
from. The probe's output names programs on the owner's PC, so it stays out of this repository. Only the
chosen certificates, their subjects and the products they were read from enter the list, and those are
public facts.

### 6. Staleness

The view cannot tell when a file was signed. When a publisher renews its certificate, its newer releases
stop folding until a row for the new certificate is measured. They are then shown unfolded, which is the
safe direction. The monthly certificate workflow also reports rows within 90 days of `not_after`. For
that, `cargo xtask check-pin-expiry`, which today reads only `certificate-pins.csv`, reads this list too. It is
never a required check.

## Owner questions

1. **The list.** Recommended: **a new list, `rules/known-publishers.csv`**, as above.
   - Alternative: keep O1 on `certificate-pins.csv` as written, which folds nothing.
   - Alternative: treat any valid signature as known. That folds anything signed with a bought
     certificate, so it is not recommended.
2. **When to fold.** Recommended: **only when no identity fact holds** (section 2).
   - Alternative: ADR 0078 as written, where O1 alone folds, even on a file that ran from Downloads.
3. **The first rows.** Recommended: **the probe on the owner's PC, and the owner picks** (section 5).
   - Alternative: a fixed starting list (Microsoft, Discord, Valve, NVIDIA, AMD, Google, Mozilla, Epic Games,
     OBS, Spotify), each measured from a file downloaded from the publisher. This is wider, but no row comes
     from a PC that plays on the servers.
4. **The display.** Recommended: **last, under one closed line, with full cards inside, the same in both
   front ends** (section 3).
   - Alternative: in the CLI, only names and publishers under the line, which is shorter but tells
     staff less.
5. **The text.** Recommended: **the table below, as drafted.**

| Key | ไทย | English |
|---|---|---|
| `fold.line` | โปรแกรม {{count}} รายการที่เซ็นโดยผู้ผลิตที่รู้จัก | {{count}} programs signed by a known publisher |
| `fold.note` | พับไว้เพราะมีลายเซ็นที่ตรวจผ่านด้วยใบรับรองที่อยู่ในรายชื่อผู้ผลิตที่รู้จักของโปรแกรมนี้ และไม่มีข้อเท็จจริงด้านตัวไฟล์ข้อใดเป็นจริง การถูกพับไม่ได้บอกอะไรด้วยตัวเอง | Folded: a valid signature with a certificate in this program's list of known publishers, and no fact about the file holds. Being folded says nothing on its own. |
| `fact.o1` | เซ็นโดยผู้ผลิตที่รู้จัก: {{product}} | signed by a known publisher: {{product}} |

## Owner decisions (2026-10-24, each as recommended)

1. **The list:** a new list, `rules/known-publishers.csv` (section 1).
2. **When to fold:** only when none of I1, I3, I4 and L1 holds (section 2).
3. **The first rows:** the probe on the owner's PC, and the owner picks the publishers (section 5).
4. **The display:** last, under one closed line, with full cards inside, in Self mode only, the same in both
   front ends (sections 3 and 4).
5. **The text:** the table under the owner questions, as drafted.

## Alternatives weighed

| Alternative | Why not |
|---|---|
| O1 on `certificate-pins.csv` alone | Its one row signs `FiveM.exe`, which is never a candidate |
| Any valid signature | A bought certificate is cheap. ADR 0035 already refuses to treat a signature as an identity |
| Match the signer's name | The subject is free text that anyone can register something close to (ADR 0035) |
| Fold on O1 even with an identity fact | A leaked publisher key would hide the one file that matters |
| Hash allow-list of files instead of certificates | Every update changes the hash. Certificates change only every one to three years |

## What is unverified

- How many candidates an ordinary evening produces, and how many the list would fold: P7's baseline.
- Whether the programs the owner's PC records are typical of the players' PCs.
- Whether any certificate chosen for the list has leaked. A leak found later removes its row; the change
  journal of the list is its git history.

## Consequences

- One more measured list to keep current. A stale row only means newer releases are not folded.
- The rules bundle carries the list, so its hash changes with every row.
- O1 becomes the first fact that moves a candidate in the order, and only downwards, into the folded line.
  ADR 0061 section 4 still forbids any number, colour scale or verdict word. The folded line counts
  programs; it does not judge them.
