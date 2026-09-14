# ADR 0035 — Checking signatures without the network, and FiveM for GTA V Enhanced

- Status: accepted
- Date: 2026-09-13

## Context

### What was waiting on this

ADR 0009 shipped `fivem_dir` with no rule and wrote the condition that ends that: *"The rule follows
once signer checking or a starter allow-list exists."* A file in FiveM's plugin folder is as often
ReShade or an overlay as anything else, and a rule's `allow` may identify legitimate software only by
`sha256` or `signer`. Until now no collector emitted `signer`, and no rule in the bundle had an `allow`
entry at all (ADR 0034). ADR 0034 names signer checking as one of the two ways a Prefetch, BAM or PCA
rule could ever become writable.

### A signer's name is not an identity

`allow.signer` was a string compared with the certificate subject. In March 2022, code-signing
certificates stolen from NVIDIA were used to sign malware and hacking tools. Those files carried the
subject "NVIDIA Corporation", exactly like NVIDIA's own
([BleepingComputer](https://www.bleepingcomputer.com/news/security/malware-now-using-nvidias-stolen-code-signing-certificates/),
[Petri](https://petri.com/nvidia-code-signing-certificates-malware/)). A rule that allowed
`signer: NVIDIA Corporation` would have exempted them. Nothing in this repository had used the field,
so correcting it costs no rule.

### Checking a signature can reach the network, where no gate here looks

ADR 0003 makes this program offline, and its gates are `cargo deny` bans on network crates and a
clippy ban on `std::net`. Both look at this program's code. Building a certificate chain and checking
revocation happen **inside Windows**: CryptoAPI fetches missing intermediates and revocation lists
from URLs that certificates name, and neither gate can see that. Microsoft's `WINTRUST_DATA`
documentation says so directly: *"To ensure the WinVerifyTrust function does not attempt any network
retrieval when verifying code signatures, WTD_CACHE_ONLY_URL_RETRIEVAL must be set in the dwProvFlags
parameter"*
([WINTRUST_DATA](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_data)).

### FiveM for GTA V Enhanced is somewhere else

`fivem_dir` read `%LOCALAPPDATA%\FiveM\FiveM.app\plugins`, which is FiveM for GTA V **Legacy**. FiveM
for GTA V Enhanced installs separately. Measured on one Windows 11 machine (build 26220) on 2026-09-13,
by listing folders and reading nothing inside the files:

| | Legacy | Enhanced |
|---|---|---|
| Program | `%LOCALAPPDATA%\FiveM\` | `%LOCALAPPDATA%\FiveM for GTAV Enhanced\` |
| User data | `%LOCALAPPDATA%\FiveM\FiveM.app\` | `%APPDATA%\FiveM for GTAV Enhanced\` — roaming, not local |
| Plugin folder | `FiveM.app\plugins` | no `FiveM.app` and no `plugins`; `gta5enhanced\asi` and `gta5enhanced\mods` instead, both empty, both created on the day of installation |

On a machine with only Enhanced installed, the collector reported that the Legacy folder was absent,
which the engine reads as "not found". It said nothing about the folder it never looked in.

**Not established: whether the Enhanced client loads anything from `gta5enhanced\asi`.** The folder's
name suggests it, and that is all. A search of the 208 files under 80 MB in the Enhanced install for
`gta5enhanced\asi`, `asi\` and `\asi\` found none of them, which proves nothing: larger files were not
searched, and a path can be built at run time. The Cfx support section for Enhanced covers
installation only.

**Amended 2026-09-13 — what was learned since, and what still is not known.**

- **Legacy's folder is confirmed from FiveM's own source.** In `citizenfx/fivem` on `master` (last push
  2026-09-07), [`code/components/asi-five/src/Component.cpp`](https://github.com/citizenfx/fivem/blob/master/code/components/asi-five/src/Component.cpp)
  iterates `MakeRelativeCitPath(L"plugins")` and calls `LoadLibrary` on every file whose extension is
  `.asi`, after skipping a short list of names it refuses. `fivem_dir`'s `plugins` location is the folder
  the Legacy client loads from.
- **The public source says nothing about Enhanced.** GitHub code search of that repository found no
  `gta5enhanced`, and `asi-five` is the only component that loads ASI files. Code search does not cover
  every file, so this is an absence of evidence, not evidence of absence.
- **Enhanced's game process starts only when a server is joined.** FiveM for GTA V Enhanced's server list
  is a separate launcher. On one Windows 11 machine (build 26220), each of 11 client logs
  (`fivem-for-gtav-enhanced.log-*`) began about ten seconds after the launcher logged a download into
  `servercache` followed by `Starting game using store: 4`, and the two launcher sessions without that
  line produced no client log. Watching file access while only the launcher is open therefore measures
  nothing about the client. Two Process Monitor attempts made that way are discarded for that reason.
- **Still not established: whether the Enhanced client reads `gta5enhanced\asi`.** Answering it by
  observation means watching file access while joining a server. Whether Cfx.re's client protection
  reacts to a file-access monitor running at that moment is not known, so that test is left to the
  owner's decision and was not run.

## Decision

### 1. A signature source on `Host`

`SignatureSource::file_signature(path) -> Result<SignatureCheck, SourceError>` is a new trait, and
`Host` requires it. It reads only the signature **embedded in** the file, and the answer is one of
four:

| `SignatureCheck` | `WinVerifyTrust` result |
|---|---|
| `Valid { signer, signer_cert_sha256 }` | `S_OK`. `signer` is the signing certificate's simple display name, for a person to read. `signer_cert_sha256` is the SHA-256 of the certificate's encoded bytes, as lowercase hex |
| `NoEmbeddedSignature` | `TRUST_E_NOSIGNATURE`, `TRUST_E_SUBJECT_FORM_UNKNOWN` (not a kind of file a signature can be embedded in) |
| `Invalid` | `TRUST_E_BAD_DIGEST`, `TRUST_E_EXPLICIT_DISTRUST`, `TRUST_E_SUBJECT_NOT_TRUSTED`, `TRUST_E_CERT_SIGNATURE`, `TRUST_E_NO_SIGNER_CERT`, `CERT_E_EXPIRED`, `CERT_E_WRONG_USAGE`, `CERT_E_REVOKED` |
| `UnverifiableOffline` | `CERT_E_CHAINING`, `CERT_E_UNTRUSTEDROOT`, `CRYPT_E_REVOCATION_OFFLINE`, `CERT_E_REVOCATION_FAILURE`, `CRYPT_E_NO_REVOCATION_CHECK` |

> **Amended 2026-09-14:** `CERT_E_UNTRUSTEDROOT` moved from `Invalid` to `UnverifiableOffline`, after it was
> measured for a genuine signature on a machine whose stores lack its root. See
> [What a missing root answers](#amendment-of-2026-09-14--what-a-missing-root-answers).

`E_ACCESSDENIED` is `SourceError::AccessDenied`. **Every other code is `SourceError::Failed`**, never
one of the four: calling a file's signature invalid on a code nobody here read would be a guess about
someone's software.

The state is `NoEmbeddedSignature` and not "unsigned", because a file can be signed through a Windows
catalog instead, and this check does not look there. That distinction was measured, not assumed; see
below.

`UnverifiableOffline` is kept apart from `Invalid` because it describes the check, not the file. A
legitimate publisher whose intermediate certificate this machine happens not to hold must not be
reported as tampered.

### 2. The only settings the product uses

`rongroi_host_windows::signature::OFFLINE`: `fdwRevocationChecks = WTD_REVOKE_NONE` and
`dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL`, with `WTD_UI_NONE` and
`INVALID_HANDLE_VALUE` for the window, so no dialog can appear. The state data is always closed with
`WTD_STATEACTION_CLOSE`, on every path.

### 3. `allow` compares a certificate's hash, never a name

`Allow { sha256, signer_cert_sha256 }` replaces `Allow { sha256, signer }`. Each entry names exactly one
64-hex digest, and the engine compares both digests without regard to ASCII case. The signer's name is
emitted for the reader and is never compared. `RULES_SCHEMA_VERSION` goes from 1 to 2: a version-1
rule that used `signer` no longer parses, and a version number is how that is said, even though no
such rule existed.

### 4. `fivem_dir` reads both editions and says what it found in each

- **Two locations.** Legacy's `plugins` folder keeps `location: plugins`. Enhanced's
  `%APPDATA%\FiveM for GTAV Enhanced\gta5enhanced\asi` is `location: enhanced_asi`. `mods` is not
  read: by its name it holds game content rather than modules loaded into the process. That is as
  unestablished as the `asi` folder being loaded, and it is written down here so that it can be
  revisited.
- **One observation per folder**: `location`, `folder` (`listed`, `absent` or `unreadable`), and
  `files` when it was listed. A machine with neither edition installed now reports two absent folders
  by name, rather than nothing. Folder observations carry no `path`; `location` already names the
  folder, and a path under a user profile is one more string for SS mode to redact.
- **One observation per file**, as before, plus `signature` and, for `valid` only, `signer` and
  `signer_cert_sha256`. A file whose signature could not be checked carries none of the three, for the
  same reason a file that could not be hashed carries no `sha256`. A `valid` answer whose certificate
  hash is not 64 hex characters emits none of the three.
- **`gaps`.** A folder that could not be read, or whose environment variable is not set, is a gap in
  every field. When the two folders fail for different reasons, `access_denied` is reported over
  `read_failed`, because it is the reason a rule may declare. With neither variable set, the run is
  `Unmeasured { read_failed }`, as before.

### 5. How "offline" is proven

- **Unit tests on every OS**: the classification of every named code, the fact that `OFFLINE` sets
  `WTD_CACHE_ONLY_URL_RETRIEVAL` and asks for no revocation, and, on Windows, that each written-out
  value equals the `windows` crate's.
- **Live tests** (`live_offline_*`, ignored by default): a file with an embedded signature is valid
  and names the same certificate `Get-AuthenticodeSignature` names; a copy changed in the middle is
  invalid; an unsigned executable and a text file have nothing embedded; a catalog-only file has
  nothing embedded.
- **The Windows CI job** switches the CAPI2 operational log on (on a runner that is thrown away),
  runs the offline live tests, and fails if the log recorded nothing from the test process, or if any
  event 53 ("Retrieve Object from Network") names it. It then clears the URL cache and runs
  `live_online_*`, which uses settings the product never uses, and fails unless event 53 appears. That
  second half is what makes an empty result evidence rather than silence.

## What a real Windows machine said

On the same Windows 11 machine, with a test binary cross-built from this change and run over SSH:

| Check | Result |
|---|---|
| `FiveM.exe` (Legacy), embedded Authenticode signature | `valid`, signer "Rockstar Games, Inc.", certificate SHA-256 equal to the one PowerShell computed from `Get-AuthenticodeSignature` |
| A copy of it with one byte changed in the middle | `invalid` |
| The unsigned test binary, and a text file | `no_embedded_signature` |
| `notepad.exe`: PowerShell reports `Catalog`, PE security directory empty | `no_embedded_signature` |
| `explorer.exe`: PowerShell reports `Catalog`, PE security directory **40,512 bytes** | `valid`, signer "Microsoft Windows" |
| `aeterna-rongroi-cli scan` | `plugins` listed with 0 files, `enhanced_asi` listed with 0 files |

The `explorer.exe` row is the reason the catalog-only live test, and the CI job that picks its file,
require an **empty security directory**. PowerShell's `SignatureType` says which signature it chose to
report, not whether an embedded one exists. The first draft of that test used `explorer.exe` and
failed on the real machine.

The CAPI2 check was **not** run on that machine. It turns on a Windows log, which is a setting change on
a machine that is not thrown away afterwards, so it runs only on the CI runner. Its first run, on the
`windows-latest` runner for this change (run `34750047733`), picked `pwsh.exe` as the embedded-signed
file and `notepad.exe` as the catalog-only one:

| Phase | Tests | CAPI2 events from the test process |
|---|---|---|
| `live_offline_*` (the product's settings) | 4 run, 4 passed | 22 — ids 10 ×6, 11 ×6, 30 ×2, 80 ×3, 81 ×3, 90 ×2 — and **no event 53** |
| `live_online_*` (settings the product never uses, URL cache cleared) | 1 run, 1 passed | **4 × event 53** |

So the log saw the offline checks, and it records a network retrieval when one happens.

## Amendment of 2026-09-14 — what a missing root answers

### The question

ADR 0036 left open what this check says about a genuine file on a PC whose certificate stores do not
hold the root its signature chains to. Microsoft documents that Windows fetches trusted roots from the
internet when they are first needed, and this check never goes online, so such a PC is ordinary. Decision
1 mapped `CERT_E_UNTRUSTEDROOT` to `invalid`, so a genuine `FiveM.exe` there might read as a signature that
does not verify, for a reason that has nothing to do with the file.

### What was measured

On the `windows-latest` runner (Windows Server 2025, image `windows-2025-vs2026` version 20260907.229.1), on
2026-09-14, in the CI step "What an
incomplete certificate chain answers offline", run `34804835053`. For each embedded-signed file, the chain
was read with .NET's `X509Chain` (no revocation, certificate downloads disabled) and the certificates the
signature carries were read from its PKCS #7 blob. The root was then exported from every registry
certificate store it was in — `SystemCertificates`, its policy and enterprise counterparts, for the machine
and the user — and deleted, the URL cache was cleared, and the ignored test
`live_chain_offline_what_an_incomplete_chain_answers` ran `WinVerifyTrust` with the product's `OFFLINE`
settings in a fresh process. Afterwards every export was imported back and the file checked again.

| File | Root | Where the root was | Signature carries the root | `WinVerifyTrust`, root removed | CAPI2 chain status | Restored |
|---|---|---|---|---|---|---|
| `pwsh.exe`, signed by Microsoft Corporation through Microsoft Code Signing PCA 2024 | Microsoft Root Certificate Authority 2011 | machine `ROOT` | no | `0x800B010A` `CERT_E_CHAINING` | `CERT_TRUST_IS_PARTIAL_CHAIN` | `S_OK`, valid |
| `git.exe`, signed by an individual developer through Microsoft ID Verified CS EOC CA 04 and Microsoft ID Verified Code Signing PCA 2021 | Microsoft Identity Verification Root Certificate Authority 2020 | machine `AuthRoot` | yes | `0x800B0109` `CERT_E_UNTRUSTEDROOT` | `CERT_TRUST_IS_UNTRUSTED_ROOT` | `S_OK`, valid |
| a copy of the unsigned test binary, signed in the step with a self-signed code-signing certificate made for it and removed from the stores before the check | that certificate | none | yes | `0x800B0109` `CERT_E_UNTRUSTEDROOT` | `CERT_TRUST_IS_UNTRUSTED_ROOT` | — |

In every row CAPI2 recorded events from the test process and **no event 53** (retrieval from the network),
and after each check the removed root was still in no store, so nothing was fetched or put back while it
ran. The intact checks before removal were `S_OK`.

- **Which of the two codes a missing root gives depends on whether the signature carries the root**, not
  on which store it was missing from: with the root absent and not in the signature the chain stops at
  the last intermediate (a partial chain); with the root in the signature the chain reaches it and finds
  it untrusted. The local AuthRoot list of roots Microsoft trusts did not make `git.exe`'s root trusted
  without the network.
- **A genuine signature that carries its root and a self-signed signature give the same code and the same
  chain status.** Nothing in `WinVerifyTrust`'s answer, offline, separates them.
- **No intermediate could be removed.** Every intermediate of both chains was carried in its signature and
  in no store, so what a missing intermediate answers was not measured. The step sets that case up only
  when an intermediate sits in a store.

### Decision

`CERT_E_UNTRUSTEDROOT` is `UnverifiableOffline`. Decision 1's own reason for keeping that state apart from
`Invalid` was that a legitimate publisher whose intermediate the machine does not hold must not read as
tampered; the measurement shows the same holds for its root, and that the answer for it is sometimes
`CERT_E_UNTRUSTEDROOT`. Offline, a root this machine does not hold as trusted cannot be told apart from a
root nobody trusts, so the check says it could not verify the chain rather than that the signature does
not verify.

**What this costs.** A self-signed signature, or any chain ending at a root no one trusts, now reads
`unverifiable_offline` instead of `invalid`. No rule outcome changes: every rule that reads `signature`
matches the two values together (ADR 0036), so such a file is `found` under the same row as before, and
only the value printed with it is weaker. `TRUST_E_EXPLICIT_DISTRUST` — a certificate this machine
explicitly distrusts — stays `invalid`, as do a changed file (`TRUST_E_BAD_DIGEST`) and a certificate
whose own signature does not verify (`TRUST_E_CERT_SIGNATURE`).

**Rejected.**

- **Keeping `invalid`.** It would tell a reviewer that a genuine `FiveM.exe` on an ordinary PC carries a
  signature that does not verify, which is the kind of statement about someone's software decision 1 set
  out not to make.
- **Telling the two apart by looking the root up in the machine's cached AuthRoot list.** It is more
  `unsafe` code to read a list that is itself fetched from the internet and can be absent or out of date on
  exactly the PCs in question, and a root Microsoft does not list would still be undecidable.
- **A fifth `signature` value for an untrusted root.** It names a mechanism rather than an answer, every
  rule's `match` would have to list it, and it would still not separate a genuine root from a forged one.

### Still not established

- **What `FiveM.exe`'s own signature carries**, and so which of the two codes it would give. Either way it
  is now `unverifiable_offline`. That its chain ends at a DigiCert root was stated earlier and is not
  verified here.
- **What a missing intermediate answers**, as above.
- **How often a player's PC lacks the root** of a given publisher. The runner is one machine with its
  stores changed by hand, not a population.

## What was rejected

**Comparing the signer's name, alone or beside the hash.** A name-only `allow` exempts stolen
certificates. Offering both leaves the unsafe option as the easy one.

**Checking running programs' images too.** The mechanism would be the same function. ADR 0010 chose not
to hash running images because of the cost, and nobody has measured what reading several hundred
executables, some of them hundreds of megabytes, adds to a scan the desktop app runs before its window
opens. That is its own decision.

**Looking up catalogs** (`CryptCATAdminCalcHashFromFileHandle2` and
`CryptCATAdminEnumCatalogFromHash`). More `unsafe`, for files — Windows' own — that do not belong in a
FiveM plugin folder. The state name says what was not looked at instead.

**Revocation checking**, even from the cache. `WTD_REVOCATION_CHECK_NONE` keeps the result the same on
a machine with a warm cache and on one without, and ADR 0003 rules out the network way.

**A separate collector for Enhanced.** Both folders answer the same question, "what does FiveM load
from here", and `location` keeps them apart.

## What this does not fix

- **Revocation is not checked.** A certificate revoked after it was stolen still verifies here. An
  `allow` entry for a publisher's certificate therefore also exempts whatever a thief signed with it,
  until someone removes the entry. The hash narrows that to one certificate; it does not close it.
- **A renewed certificate is a different hash.** An `allow` entry has to be updated when a publisher
  renews, typically every one to three years.
- **Timestamped signatures stay valid after the certificate expires**, which is `WinVerifyTrust`'s
  default without `WTD_LIFETIME_SIGNING_FLAG`. Nothing was measured about how the 2022 NVIDIA
  certificates' signatures verify in user mode.
- **Whether Enhanced loads from `gta5enhanced\asi` is not established**, and neither is whether it
  loads plugins from anywhere else. If it does, `fivem_dir` does not see that folder. Legacy's `plugins`
  folder is confirmed from FiveM's source; see the amendment under Context.
- **A catalog-signed file is `no_embedded_signature`.** That is accurate, and it is not "unsigned".
- **A signer can be a person.** Individual developers get code-signing certificates in their own name;
  one of the embedded-signed programs on the measured machine is signed that way. The name is shown in
  Self mode. SS mode lists no unmatched observation, so today it is counted there; a future rule that
  matched such a file would show it.
- **No rule reads any of this yet.** The `fivem_dir` rule ADR 0009 waits for is now writable, and it is
  a separate change with its own false-positive argument.
  > Written by ADR 0036: seven rules, and `FiveM.exe` of both editions read beside the plugin folders.
- **How long a check takes was measured only for a few files** — the three offline live tests took
  0.48 s together — not for a large plugin folder.

## Consequences

- `rongroi-host`: `SignatureCheck`, `SignatureSource`, and `Host: SignatureSource`. `NonWindowsHost`
  reports `Unsupported`. `FixtureHost` reads `signature: { state, signer, signer_cert_sha256 }` per
  file and refuses a signer beside any state but `valid`.
- `rongroi-host-windows`: `signature.rs`, and four more `windows` features: `Win32_Security_WinTrust`,
  `Win32_Security_Cryptography`, `Win32_Security_Cryptography_Catalog` and
  `Win32_Security_Cryptography_Sip`. The gates were read from the `windows` 0.62.2 sources.
- `rongroi-core`: `Allow::signer_cert_sha256`, `RULES_SCHEMA_VERSION` 2, and `is_allowed` compares
  digests only.
- `fivem_dir` declares eight fields. Every fixture that set `%LOCALAPPDATA%` now sets `%APPDATA%`,
  including the three baselines: every Windows account has both. Two fixtures are added,
  `fivem-dir-signatures` and `fivem-dir-enhanced-asi`. Report snapshots change for the schema version
  and for `fivem_dir`'s new observations.
- The SS consent question, in the CLI and in the desktop app, names both editions' plugin folders and
  their signatures.
- The Windows CI job gains the CAPI2 step.
- **Amendment of 2026-09-14:** `classify` maps `CERT_E_UNTRUSTEDROOT` to `UnverifiableOffline`, and the job gains
  the step "What an incomplete certificate chain answers offline", which removes roots from the stores of
  the runner, runs `live_chain_offline_what_an_incomplete_chain_answers` against the measured codes and
  restores the stores. The descriptions and `falsepositives` of the three "no embedded signature that
  verifies" rules, and ADR 0036's open item, say what was measured.
