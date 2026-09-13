# ADR 0036 — The first `fivem_dir` rules, and the signer of FiveM.exe

- Status: accepted
- Date: 2026-09-13
- Amends: ADR 0009 (what `fivem_dir` reads), ADR 0035 (the same)

## Context

ADR 0009 shipped `fivem_dir` with no rule and wrote the condition that ends that: *"The rule follows
once signer checking or a starter allow-list exists."* ADR 0035 shipped signer checking. Every file
directly inside Legacy's plugins folder and Enhanced's `gta5enhanced\asi` folder now carries
`signature` — `valid`, `no_embedded_signature`, `invalid` or `unverifiable_offline` — and, when `valid`,
`signer` and `signer_cert_sha256`. A file whose signature could not be checked carries none of the three
(ADR 0009: a per-item failure omits a field and is never a gap).

This change also asks a second question of the same mechanism: does FiveM's own executable carry the
signature it is published with? That means reading a file ADR 0009 and ADR 0035 do not name, so it is
decided here.

### What is known about these folders

- **Legacy's plugins folder is where graphics mods go.** The Cfx.re forum's own how-to for ReShade
  (September 2025) says to *"copy `dxgi.dll` and paste it into your `plugins` folder"*, meaning
  `%localappdata%\FiveM\FiveM.app\plugins`, and ReShade keeps `ReShade.ini`, a preset `.ini` and
  `ReShade.log` beside itself ([forum.cfx.re](https://forum.cfx.re/t/how-to-install-reshade/5352795)).
  That is a community guide on the vendor's forum, not vendor documentation. It is the whole of this
  project's evidence that FiveM loads from that folder, and it is also the reason a file there is as
  often ReShade, ENB, an overlay or a text file as anything else.
- **Whether FiveM for GTA V Enhanced loads from `gta5enhanced\asi` is not established** (ADR 0035), and
  nothing found since changes that.
- **Text files never carry an embedded signature.** ADR 0035 maps `TRUST_E_SUBJECT_FORM_UNKNOWN` to
  `no_embedded_signature`, and its live test measured a text file as exactly that.

### What was measured

On one Windows 11 machine, build 26220, on 2026-09-13, read-only, by listing folders, by
`Get-AuthenticodeSignature` with the certificate's `GetCertHash('SHA256')`, and by this program's own
check cross-built from this change:

| | Legacy | Enhanced |
|---|---|---|
| Program folder | `%LOCALAPPDATA%\FiveM\` — holds `FiveM.exe`, `FiveM.app\`, a shortcut and a manifest | `%LOCALAPPDATA%\FiveM for GTAV Enhanced\` — holds `FiveM.exe`, `modify.exe`, `sdk_tools.dll`, three folders and two other files |
| `FiveM.exe` embedded signature (PowerShell) | `Valid`, `Authenticode`, timestamped by DigiCert | the same |
| Signer | `CN="Rockstar Games, Inc.", O="Rockstar Games, Inc.", L=New York, S=New York, C=US` | the same |
| Issuer | `DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1` | the same |
| Certificate validity | 2026-07-21 00:00:00Z to 2027-09-05 23:59:59Z | the same |
| Certificate SHA-256 | `65866007102ff66498c1ef739cf23dff71ae3d08da0d9d759b89d1a409c4208f` | the same |
| This program's check, elevated | `valid`, "Rockstar Games, Inc.", the same certificate SHA-256 | the same |
| This program's check, limited token (a scheduled task at `/rl LIMITED`) | the same | the same |
| Plugin folder files | `plugins` listed, 0 files | `enhanced_asi` listed, 0 files |

The same hash had been read from the same machine once before this change; it was measured again here,
from both editions, rather than relied on. It was measured from the files as FiveM installed and
updated them on that machine, **not** from a fresh download from Cfx.re, which was not made.

**The certificate became valid on 2026-07-21**, less than two months before the measurement. A
signature is made while its certificate is valid, so any `FiveM.exe` signed before that date was signed
with a different certificate. That is arithmetic on the certificate, not a measurement of an older
`FiveM.exe`, and nothing is known about the earlier certificate — not even its signer name.

**Every rule was then made to fire on the same machine.** The CLI was run with `%LOCALAPPDATA%` and
`%APPDATA%` pointed, for that one process, at a folder this change created and deleted afterwards,
holding copies of real files. Nothing outside that folder was written.

| Placed as | What it was | Result |
|---|---|---|
| Legacy `FiveM.exe` | a copy of `explorer.exe` (embedded Microsoft signature) | `valid`, "Microsoft Windows" → **found** by the other-certificate rule |
| Enhanced `FiveM.exe` | a copy of the real `FiveM.exe` with one byte changed in the middle | `invalid` → **found** by the no-verifying-signature rule |
| `plugins\ReShade.ini` | a one-line text file | `no_embedded_signature` → **found** |
| `plugins\signed-copy.dll` | a copy of the real `FiveM.exe` | `valid`, Rockstar → **found** by the valid-signature rule |
| `plugins\locked.dll` | a file another process held open with no sharing | no `sha256`, no `signature` → **found** by the could-not-be-checked rule |
| `asi\copy.asi` | a copy of the real `FiveM.exe` | `valid` → **found** by the Enhanced valid-signature rule |

The same run in SS mode showed all six paths as `%USERPROFILE%\…`; the account name appeared nowhere
in the JSON.

## Decision

### 1. `fivem_dir` reads `FiveM.exe`

Two more locations, both under `%LOCALAPPDATA%`: `legacy_exe` (`FiveM\FiveM.exe`) and `enhanced_exe`
(`FiveM for GTAV Enhanced\FiveM.exe`). The collector lists the program folder, takes the one entry
whose name is `FiveM.exe` (ASCII case folded) and is a file, and reports it exactly as a plugin file:
`location`, `path`, `sha256`, `signature` and, when `valid`, `signer` and `signer_cert_sha256`.

- **Nothing else in the program folder is reported**, not even that it exists. The names of its other
  entries are read by the listing and dropped. A test asserts `modify.exe` and the manifest reach no
  part of the report.
- **An absent folder or an absent `FiveM.exe` produces no observation.** The plugin folders' own
  observations already say which editions are installed; a third way of saying it would be read by no
  rule.
- **A program folder that cannot be listed is a gap in every field**, as a plugin folder is. It adds no
  folder observation, because a program folder has none.
- No other executable is read — not `modify.exe`, not anything under `FiveM.app`. Each would be its own
  question with its own false positives.

### 2. Seven rules, which between them show every file the collector reports

| Rule | `match` | Strength |
|---|---|---|
| A file in FiveM's plugins folder has no embedded signature that verifies here | `location: plugins`, `signature: [no_embedded_signature, invalid, unverifiable_offline]` | `presence` |
| A file in FiveM's plugins folder carries a valid embedded signature | `location: plugins`, `signature: valid` | `presence` |
| The same two for `location: enhanced_asi` | | `presence` |
| A FiveM file's signature could not be checked | `path\|exists: true`, `signature\|exists: false` | `context` |
| FiveM.exe has no embedded signature that verifies here | `location: [legacy_exe, enhanced_exe]`, `signature: [no_embedded_signature, invalid, unverifiable_offline]` | `presence` |
| FiveM.exe is validly signed, but not with the certificate this rule knows | `location: [legacy_exe, enhanced_exe]`, `signature: valid`, `allow: signer_cert_sha256: 6586…208f` | `presence` |

All are `experimental`: no real plugin file has ever met them, and the pin is a snapshot of one
certificate.

**Why the signature answers partition the rules.** `match` has no negation, so "not valid" is written
as the list of the other three. A file observation carries exactly one `signature` value or none, so
every plugin file lands in exactly one of three rows — valid, not verifying, not checked — and every
`FiveM.exe` either in one of the three or excused by `allow`. No file the collector reports is left an
unmatched observation, which SS mode would only count, and no file appears under two rules. The folder
observations stay unmatched.

**Why signed and unsigned are separate rules.** What a reviewer can do next differs. A valid signature
names a publisher and a certificate that can be looked up, and it is the only row an `allow` entry can
ever shorten. A file with nothing verifiable has only its path. One rule would hide that difference
inside the observations.

**Why `unverifiable_offline` sits with "does not verify" rather than alone.** It is a limit of the
check, and a rule of its own would read as a separate finding about the file. It is not left out
either: a list without it would send such a file to `not_found` under every rule, which is the silent
outcome this ADR is about. The value is printed with each observation, and each rule's
`falsepositives` explains it.

**Why one rule per folder and not one for both.** The Enhanced rule has to say that the folder is not
known to be loaded; the Legacy rule does not. A title shared between them would either overclaim for
Enhanced or underclaim for Legacy.

**Why `presence`.** A file with a given signature exists; nothing shows it ran. `tamper` would say
something was altered, which an unverifiable signature, a renewed certificate or an unsigned ReShade
does not show. The could-not-be-checked rule is `context`: it says something about the check. None is
`posture`, so a `not_found` of any of them is counted, never listed, in SS mode (`view::ss_lists`).

**`unmeasured_when: [not_windows]` for all seven, and `access_denied` deliberately undeclared.** These
folders are inside the player's own profile, and a plugins or program folder its owner cannot list is
not the state of an ordinary install, so SS mode lists it.

### 3. Tracing the engine: no failed read becomes a quiet answer

| Situation on the machine | What the collector emits | What the rules say |
|---|---|---|
| A plugin or asi folder, or a program folder, cannot be listed | a gap in every field | **every** `fivem_dir` rule `unmeasured`, including the `exists: false` rule, because `evaluate_rule` checks gaps before an absence condition (ADR 0029). Tested on both fixtures |
| One file's signature check fails | that file without `signature` (and usually without `sha256`) | the could-not-be-checked rule is **found** with that file's path; the other rules do not match it |
| Windows answers `unverifiable_offline` | `signature: unverifiable_offline` | **found** under the "does not verify" rule of its location |
| A `valid` answer whose certificate hash is malformed | none of the three signature fields (ADR 0035) | **found** under could-not-be-checked |
| Only the hash read fails | no `sha256`, a `signature` | the signature rule of its answer; only `allow` by `sha256` is affected, and no rule has one |
| `FiveM.exe` is not there | nothing | both client rules `not_found`, and their `description` says an install without `FiveM.exe` is `not found` too |

**What the engine forces, and where it was answered.** ADR 0009's per-item rule means a failed check is
not a gap. So a `not_found` under "has no embedded signature that verifies" speaks only for the files
whose signature was checked, and its own row cannot say that one file was not. Two fixes at a lower
layer were considered and rejected:

- **Gap `signature` for the run when any one file's check fails.** Gaps are per run, not per location:
  one locked ReShade log would make both `FiveM.exe` rules `unmeasured`, and the could-not-be-checked
  rule itself would become `unmeasured`, because an absence condition consults gaps first. The file
  that failed would then be named nowhere.
- **Emit a fifth `signature` value such as `unchecked`.** It would be a signature state that is not
  something Windows said, in a field ADR 0035 defines as what Windows says.

So it is answered at the rule layer: the failure is its own `found` row, naming the file, and every
related rule's `description` says the failed file is shown there and not in its row.

**Recorded, not fixed.** Gaps being run-wide has a cost these rules make visible: an unreadable
Enhanced program folder makes the Legacy plugins rules `unmeasured` too, though that folder was read.
Per-location gaps would need a change to `CollectorRun`, which is not this ADR's.

### 4. The pin

`allow: signer_cert_sha256: 65866007…c4208f` is the one `allow` entry in this ADR, measured as above
from both editions. **No other `allow` entry is added** — not for ReShade, ENB, an overlay or anything
else — because none was measured from a file its publisher released, and an entry from memory is a
claim nobody can check.

**When the publisher renews, the entry goes stale for every player at once.** The certificate is valid
until 2027-09-05, and every `FiveM.exe` signed with its successor will make the other-certificate rule
fire. The rule's `falsepositives` tells a reviewer what to do: treat a row that shows the same signer
on many players' reports as saying nothing, check the certificate of a `FiveM.exe` freshly installed
from Cfx.re on a machine of their own, and report it. The fix is a second `allow` entry measured the
same way, **beside** the first: a player who has not updated still has a file the first one signed.

The same rule fires, before any renewal, for a `FiveM.exe` signed before 2026-07-21. How often a player's
`FiveM.exe` is that old is not known. That FiveM replaces `FiveM.exe` when it starts is what the rule
text assumes, and it is **not measured** here beyond one fact consistent with it: the installed files
carry a certificate issued two months before the measurement.

### 5. Baselines

`baseline-consumer-win11` and `baseline-elevated-win11` describe FiveM installed with an empty plugins
folder. They now also describe `%LOCALAPPDATA%\FiveM\` holding `FiveM.app` and `FiveM.exe` with the
measured hash and signature — a description of an ordinary install, recorded in
`fixtures/hosts/PROVENANCE.md` as measured, with the date and build. The consumer baseline is
`elevated: false`, which the limited-token run above supports.

What `check-baseline` then confronts, measured:

| Rule | Confronted on the baselines? |
|---|---|
| The two client rules | **yes**, by `FiveM.exe`: one condition away (`signature`) and allowed, respectively |
| Could not be checked | **yes**, by `FiveM.exe`: it carries `signature` |
| The two valid-signature plugin rules | **yes, but only by `location`**: `FiveM.exe` differs from them in that condition alone. That checks the spelling `signature: valid` and says nothing about plugin folders — ADR 0033's "a confronted rule is not a correct rule" applies with force |
| The two "does not verify" plugin rules | **no** — two conditions away. `rules/unconfronted.csv` rows say why and what ends them: a baseline plugin file measured from a published release, never an invented "ordinary plugin" |

That the pin is checked was proven by breaking it: changing its last hex digit made `check-baseline`
fail with the rule `found` on both baselines.

### 6. SS mode now shows plugin file paths

Until this ADR every plugin file was an unmatched observation, listed in Self mode and counted in SS
mode (ADR 0014). Now each one matches a rule, so in SS mode its path, hash, signature and signer are
shown to the person watching. The consent question already names the plugin folders and their
signatures; it now names `FiveM.exe` as well. Redaction was tested on these rows — both in fixtures
(`fivem_dir_plugin_present_ss_view`, `fivem_dir_client_exe_ss_view_redacts_both_programs_and_shows_nothing_else`)
and on the real machine above.

## What was rejected

- **One rule, "a file is in FiveM's plugins folder".** It would treat a signed overlay and an unsigned
  file the same, and leave `signature` unused a release after it was built for this.
- **Narrowing the plugin rules to `.dll` and `.asi`.** It would drop the ReShade text files that make up
  most of the noise. What FiveM loads by extension is not established, and a rule narrowed by a name
  shape is the kind ADR 0034 describes: a rename leaves it silent.
- **A starter `allow` list from memory**, for the reason in decision 4.
- **Reading `modify.exe` and the other executables beside `FiveM.exe`.** Not asked for, and each needs
  its own measurement.
- **Declaring `access_denied`**, for the reason in decision 2.

## What is not established

- **One machine.** Both editions, both tokens, one Windows build. Nothing here is a population.
- **Whether `unverifiable_offline` or `invalid` happens to `FiveM.exe` on a machine that has never
  fetched DigiCert's root.** Microsoft documents that *"By default, Windows downloads the CTLs from the
  Internet via an automatic mechanism called the CTL Updater"*
  ([Certificates and trust](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-trust)),
  and this check never goes online. Which of ADR 0035's codes a missing root produces was not measured,
  and ADR 0035 maps `CERT_E_UNTRUSTEDROOT` to `invalid`; a missing root could therefore read as "does not
  verify". The client rule's `falsepositives` says so.
- **Beta or test builds of the client**, and whether they are signed with the same certificate.
- **The certificate that signed `FiveM.exe` before 2026-07-21.**
- **The pin was not compared with a fresh download from Cfx.re.** It was measured from installed files
  on one machine.
- **Whether Enhanced loads from its `asi` folder** (ADR 0035), unchanged.
- **Redaction outside `X:\Users\<name>`.** A profile redirected elsewhere keeps its account name in these
  paths in SS mode, as it does in every other collector's. Unchanged by this ADR.
- ~~The Thai text of the seven rules has not been read by a native speaker.~~ **Amended 2026-09-13:** the
  project owner read the Thai text of every rule in the bundle, as `docs/rules-reference.th.md` renders it
  (18 rules, these seven among them), and approved it.

## Consequences

- `fivem_dir` declares no new field; it gains two `location` values. Two fixture hosts are new,
  `fivem-dir-client-exe` and `fivem-dir-client-folder-denied`.
- The bundle goes from 6 rules to 13. Every report snapshot gains seven evidence entries; on a fixture
  that sets no `%LOCALAPPDATA%` those are `unmeasured / read_failed`, which SS mode always lists.
  `fivem_dir_plugin_present_ss_view` now shows the two plugin paths, redacted, where it used to assert
  the file name was absent.
- `rules/unconfronted.csv` gains two rows.
- The CLI's and the desktop app's consent text, `PRIVACY.md`, `docs/architecture.md`, both screenshare
  guides and `docs/rules-authoring.md` name `FiveM.exe` and the per-item-failure rule pattern.
- ADR 0009's "The rule itself is still to be written" and ADR 0035's "No rule reads any of this yet" are
  answered here; both keep their text, with a pointer.
