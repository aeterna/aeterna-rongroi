# ADR 0090 — The antivirus products Windows reports

- Status: proposed — drafted 2026-11-01 for owner decision Q21 of the product line (2026-10-28): this collector
  is built before any server may block on a Defender rule, and until then a Defender rule gives a server a
  warning only. The questions in "Owner decisions" are open. Spike lane S11 (does another antivirus make the
  Defender rules fire, and why) has not run: no test machine with another antivirus yet (P4)
- Date: 2026-11-01
- Related: AGENTS.md hard rules 2–5 and 9, ADR 0011 (WMI declined for one value), ADR 0030 (the reasons),
  ADR 0035 (`signature`), ADR 0052 (scan tiers), ADR 0056 (`os_image`, `service_windefend`,
  `installation_type`), ADR 0057 (`install_marker`, Defender's platform folder), ADR 0059 (Defender 5001),
  ADR 0060 (`defender_exclusion`, `path_kind`), ADR 0061 and ADR 0062 (cross-source statements), ADR 0069
  (WMI declined again), ADR 0076 (lab replay), ADR 0084 (rule 9 applied), ADR 0089 (proposed: the product
  line and the `posture` profile)
- Amends: ADR 0089's posture profile, once both are accepted (section 6 names `antivirus_product` as read
  beside the Defender `posture` rules)

## Context

Six rules in the bundle are about Microsoft Defender:

| Rule | Strength | What it reads |
|---|---|---|
| `evtx/defender/defender-real-time-protection-turned-off` | context | a 5001 in Defender's log (ADR 0059) |
| `defender_exclusion/fivem/fivem-folder-excluded` | posture | Defender's exclusions (ADR 0060) |
| `os_image/windows-components/defender-service-disabled` | posture | `WinDefend`'s start type (ADR 0056) |
| `os_image/windows-components/defender-service-not-registered` | posture | no `WinDefend` key (ADR 0056) |
| `install_marker/windows-components/defender-platform-folder-absent` | posture | Defender's platform folder (ADR 0057) |
| `evtx/timeline/defender-detection` | context, timeline selector | detections' times (ADR 0059) |

Each of them describes Defender alone. None can say whether **another** antivirus is on the PC. That matters
because Windows is described as stepping Defender aside when another antivirus registers with Windows
Security Center: Defender's real-time protection turns off, or Defender runs in a passive mode. A row that
reads "Defender is off" then has two very different ordinary readings, "the player turned it off" and "the
player installed another antivirus", and today the report holds nothing that tells them apart.

What this repository has established, and what it has not:

- **Measured.** On the development PC (ADR 0059, 2026-09-30) Security Center listed one antivirus product,
  Defender, with real-time protection on. That is the only measurement here of what Security Center lists.
- **Unverified.** Whether Defender writes a 5001 when another antivirus registers (ADR 0059, "What is
  unverified"). Whether Defender's service start type becomes `disabled`: `defender-service-disabled` says in
  its `description` that "installing another antivirus does exactly this", and ADR 0056 states it too, but no
  ADR records a measurement of it. Whether Defender's exclusions are kept, cleared or ignored when it steps
  aside. These are spike lane S11's questions, and they need a PC with another antivirus (P4).

The product line raises the stakes. Under ADR 0089 a server may ask for a `posture` scan and gate on what it
finds. The owner decided on 2026-10-28 (Q21) that a server may not block on a Defender rule until the report
also says which antivirus products Windows reports; until then a Defender rule gives a server a warning only.
That decision lives in the Server Kit, not here. What this repository owes it is the fact.

A new kind of source needs an ADR (CONVENTIONS.md §8).

## Decision

### 1. The source: Windows Security Center, through its documented API

Windows Security Center keeps the list of security products registered with it, by type. Two ways read it:

- **The WSC API** (`iwscapi.h`): `IWSCProductList::Initialize(WSC_SECURITY_PROVIDER_ANTIVIRUS)`, then
  `get_Count` and `get_Item`, and on each `IWscProduct`: `ProductName`, `ProductState` and
  `RemediationPath`. Documented on Microsoft Learn. Its pages give "Minimum supported client: Windows 8" and
  "Minimum supported server: None supported" (read 2026-11-01). `ProductState` returns
  `WSC_SECURITY_PRODUCT_STATE`, a documented enumeration: `ON`, `OFF`, `SNOOZED`, `EXPIRED`.
- **WMI**: class `AntiVirusProduct` in namespace `root\SecurityCenter2`, with `displayName`, `productState`,
  `pathToSignedProductExe`, `pathToSignedReportingExe` and `timestamp`. Microsoft does not document this class
  on Learn, and `productState` is a number whose bit layout Microsoft has never published (section 2).

**Decided: the WSC API.** Its state is documented, so nothing has to be decoded by a convention nobody owns.
And ADR 0011, ADR 0038 and ADR 0069 each declined WMI as "a far larger surface than one value is worth"; this
ADR does not overturn that for one list.

Read in the vendored `windows` 0.62.2 source on 2026-11-01, rather than assumed: `IWSCProductList`,
`IWscProduct` with `ProductName`, `ProductState` and `RemediationPath`, the class id `WSCProductList`, the
`WSC_SECURITY_PRODUCT_STATE_*` constants and `WSC_SECURITY_PROVIDER_ANTIVIRUS` are generated under the
`Win32_System_SecurityCenter` feature, with `Win32_System_Com`, which `rongroi-host-windows` already enables
for the save dialog (ADR 0073). No hand-written `extern "system"` is needed.

The cost of the WSC API is the path. `RemediationPath` is documented only as "the remediation path for the
security product", displayed in Security Center's interface. It is **not** documented to be the product's
program file; WMI's `pathToSignedProductExe` is named as one, but is itself undocumented. Probe A0 (Order of
work) reads both on the same PC. If `RemediationPath` does not name a program file there, the path question
comes back to the owner (Owner decisions, question 1) before any code.

**Not read:**

- `SignatureStatus` (definitions up to date or not) and `ProductStateTimestamp`. No rule needs them. The
  timestamp is a string whose format the page does not give.
- `ProductGuid` and `ProductIsDefault`. A GUID names the registration, not the product, and is not needed to
  tell two products apart in one report.
- Firewall and antispyware providers. Only `WSC_SECURITY_PROVIDER_ANTIVIRUS`.
- `MSFT_MpComputerStatus.AMRunningMode` (Defender's own Normal, Passive or EDR Block Mode). No collector reads
  it; the only reader in this repository is the Windows CI workflow, through `Get-MpComputerStatus` (ADR 0038).
  It is WMI in another namespace, and it says what Defender thinks of itself, not what else is registered. It
  is a later ADR if S11 shows it is needed.

Read-only (hard rule 2): the collector calls `CoInitializeEx`, `CoCreateInstance(WSCProductList)`,
`Initialize`, `get_Count`, `get_Item` and the three getters, and nothing else from that feature.
`IWSCDefaultProduct::SetDefaultProduct`, `WscRegisterForChanges`, `WscRegisterForUserNotifications` and
`WscUnRegisterChanges` are banned in `clippy.toml` in the same pull request. No child process, no network.

### 2. `productState` is not decoded

If the WMI path is ever used (Owner decisions, question 1), its `productState` is kept as the raw number in a
field of its own and **not decoded**. The common reading — one byte for the provider type, one for "on or
off", one for "definitions up to date" — is a convention from forum posts and vendor blogs, not from
Microsoft. A rule built on it would state as fact a layout nobody can point to. **Unverified**, and it stays
out of the code.

With the WSC API, nothing is decoded: `ProductState` is the enumeration. A value outside the four documented
ones is emitted as `state: other`, with the number in `state_value`.

### 3. The collector: `antivirus_product`

- **Id** `antivirus_product`, file `crates/rongroi-collectors/src/antivirus_product.rs`. **Tier** `standard`
  (ADR 0052): it lists software installed on the PC, as `driver_service` and `autostart` do, and carries no
  account or server identity.
- **One observation per product**:

| Field | Kind | From |
|---|---|---|
| `display_name` | text | `ProductName`, as Security Center gives it |
| `state` | text | `on`, `off`, `snoozed`, `expired`, or `other` |
| `state_value` | number | the raw enumeration value, only when `state` is `other` |
| `path` | text | the product's program file, when section 1's question resolves to a drive-rooted file |
| `path_withheld` | text | `unredactable_form`, in place of `path` when the path is not drive-rooted (as `bam`'s) |
| `file_unread` | text | why the file was not opened or not fully read (below) |
| `path_kind` | text | as `autostart`'s (ADR 0060): `windows`, `program_files`, `program_data`, `user_profile`, `other` |
| `sha256`, `signature`, `signer`, `signer_cert_sha256` | text | that file, read as `autostart` reads a file (ADR 0035) |

- **One summary observation**: `products` (how many Security Center lists) and `products_on` (how many of those
  say `on`). A count of facts that hold, not a score: nothing adds it to anything (hard rule 3).
- **Hashing and signatures** use the existing `SignatureSource` and hashing code, under a wall-clock budget of
  its own checked before each file, with a `budget_spent` gap on `sha256` and `signature` when it runs out, as
  `driver_service` does. A product's file under `%SystemRoot%` is checked like any other (ADR 0084). The
  budget's number is set in the pull request, after A0 times the files; a PC is expected to list one to three
  products, so it should be small. **Unverified** until measured.
- **Only a file on a fixed local drive is opened.** The registering program chooses the path, so it can name a
  network share, and opening it would make this program connect to another machine, sending the account's
  credentials to it. That is network access in all but name (hard rule 1). Before the file is opened, all of
  The file is read through the host's local-drive check (ADR 0091), the one every collector that reads by
  path uses, and this collector adds no check of its own:
  - a `\\server\share\…` or `\\?\UNC\…` path, or a device path, is refused as `not_drive_rooted`. The path
    is then withheld with `path_withheld: "unredactable_form"`, as `bam` withholds one (ADR 0023), so a server
    name never reaches the report;
  - a letter that is not a fixed or removable drive (a mapped network drive, optical, RAM) is refused as
    `not_local_drive`;
  - a junction, symbolic link or mount point on the way is followed only while its target stays on a local
    drive; one that leads to a share is refused as `link_off_local_drive`, and one the program cannot show is
    local (a volume name, a cloud placeholder whose data is not on the disk, an unknown reparse tag) as
    `link_unsupported`.

  A refused path keeps its `path` (or `path_withheld`) and gets no `sha256` or `signature`, with
  `file_unread` carrying ADR 0091's reason. That is a fact about the path, not a gap, so no rule turns
  `unmeasured` over it (ADR 0084's reasoning for `file_unread`). ADR 0091's own unverified points (that the
  attribute and reparse reads on a link to a share stay off the network) apply here too; A0 does not repeat
  them.
- **The name is not a key.** `display_name` is whatever the registering program wrote. It is never compared to
  a list, never used to pick Defender out, and never decides anything (section 5).
- `display_name`, `state`, `path`, `path_kind` and the summary fields go into `CONVENTIONS.md`'s glossary;
  `path_kind`, `sha256`, `signature`, `signer` and `signer_cert_sha256` are reused with their meaning, so the
  glossary row for `path_kind` gains this collector. `product_name` is not reused: it is `os_image`'s
  Windows `ProductName`, another idea.

### 4. Outcomes: found, nothing listed, unmeasured

- **Not Windows** → `not_windows`.
- **A Server edition** → `not_on_this_os`, decided before any call by reading `InstallationType` from the key
  `os_image` already reads (ADR 0056). Microsoft lists no supported server for the WSC API. That a Server
  answers with an error rather than an empty list is **unverified**; deciding by the edition first means the
  answer never depends on it.
- **No product listed on a client** → `Measured` with the summary observation `products: 0`. It is an answer,
  the way ADR 0011 made "no TPM" an answer, not `source_empty`. Whether Security Center can list nothing for a
  moment after sign-in, before products register, is **unverified**; A0 scans straight after a sign-in.
- **The Security Center service (`wscsvc`) stopped or disabled** → what the API answers is **not measured**.
  Until A0 shows a distinct answer, every failed call is `read_failed`, which a rule cannot declare away, so SS
  mode lists it. If A0 shows a distinct answer, it becomes `service_disabled`, and `rules/AGENTS.md`'s list of
  who reports that reason gains this collector.
- **Refused** → `not_admin` without administrator rights, `access_denied` with them.

**Administrator rights.** Expected **not** to be needed, but **unverified**: the WSC API's pages state no
rights requirement. Spike S9 (2026-10-31) found that among the posture collectors only `defender_exclusion` needs an
elevated scan, and the Connect sidecar's elevation rests on that. Both are inferences, not measurements of this
API. A0 reads the list at Medium and at High integrity. If Medium is refused, ADR 0089's elevation section
gains this collector beside `defender_exclusion`.

**Fixtures.** `FixtureHost` gains an `antivirus_products:` block. A fixture with no such block answers
`Unsupported`, never "nothing listed" (ADR 0011: a fixture's silence is not a default).

### 5. How the Defender rules change: they are read beside the list, and nothing else

**No Defender rule's `match`, `strength`, `status` or `unmeasured_when` changes.** No rule reads
`antivirus_product` to fold, hide, move down, grey out or soften a Defender row because a product is listed.
That would be vouching (hard rule 9): a registration says what a program told Security Center, and how Security
Center checks a program that registers is not documented on the pages read for this ADR. A cheat or its
installer could register a "product" that reports itself `on` (**unverified** how hard that is; it is assumed
possible, as a stolen signing key is in rule 9). A listed product is a fact about what is registered, never a
reason a Defender row means less.

What changes:

- **A cross-source statement of a new kind, `antivirus`** (ADR 0061 section 3, ADR 0062): "Windows Security
  Center lists these antivirus products", each with its `display_name`, its `state` and its file's signature
  fact, or the reason the list could not be read. It is not evidence: no state, no rule id, never counted in
  `ListedCounts` or `HiddenCounts`. Self mode shows it always. SS mode shows it when the view lists a row of a
  rule tagged `defender`. The five Defender rules without that tag gain it; a tag is not a match field, so no
  rule's answer changes.
- **Each Defender rule's `falsepositives`** says, where it names another antivirus as an ordinary cause, that
  the report's antivirus list shows what Security Center lists, and that a product listed there is a fact
  about what is registered, not proof that it scans.
- **`docs/rules-reference.md` and `.th.md`** are regenerated by `cargo xtask rules-reference`, and
  `rules/i18n/th.yaml` gets the new text, in the same pull request.
- **What `defender-service-disabled` and ADR 0059 claim about another antivirus is not changed here.** S11
  measures it; the text changes after, in its own pull request, with the measurement.

For the product line: the Connect record carries the view, so a server sees the same list beside the same
Defender rows. Whether a server then blocks is the server's decision (ADR 0089, Q21), and nothing in this
repository makes it.

### 6. The `posture` profile (ADR 0089)

ADR 0089 first defined the `posture` profile as "the collectors behind the rules marked `posture`". A collector
that only feeds a statement is not behind any rule, so under that sentence `antivirus_product` would not run in
a `posture` scan, and a server would gate on Defender rows without the list Q21 asks for. ADR 0089, still an
open pull request, is being changed so that the profile also runs "the collectors an accepted ADR names as read
beside posture rules".

**This ADR is that naming, once it is accepted:** `antivirus_product` is read beside the `posture` rules about
Microsoft Defender (section 5), so the `posture` profile runs it. Until both ADRs are accepted, neither the
profile nor the Connect consent screen lists it. If Owner decisions question 2 is answered yes, the rule there
also puts the collector behind a `posture` rule, and the profile runs it under either sentence.

### 7. Privacy

- `path` goes through SS-mode redaction like every path (hard rule 5, ADR 0049). A product installed per user
  is under a profile root, which redaction reaches.
- `display_name` is shown in SS mode. It is a product's name, like `signer`. It is not an account identifier.
  A registering program chooses it, as it chooses a `Run` value's name (ADR 0060 withheld `entry` because a
  task's path can carry a SID, which a product name does not ordinarily); if A0 or a later report shows a name
  that carries a person's data, it joins `SS_WITHHELD_FIELDS`.
- `PRIVACY.md`, the CLI's consent text and the desktop's consent text name the collector in the pull request
  that registers it: the antivirus products Windows lists, their state, and their program files' hashes and
  signers.

## Tests and fixtures

- **Collector, on `FixtureHost`**: two products, one `on` and one `off`; `products: 0`; a Server edition
  (`not_on_this_os`, no call made); a refused read (`not_admin`, `access_denied`); a failed call
  (`read_failed`); a state value outside the four (`other`, `state_value`); a UNC path `\\server\share\av.exe`
  (`path_withheld`, `file_unread: not_drive_rooted`, nothing opened); a path on a mapped network letter
  (`file_unread: not_local_drive`, nothing opened); a path through a junction to a share
  (`file_unread: link_off_local_drive`, the file not opened); in each, the fixture
  host fails the test if the file's content is read; a spent budget (gaps on `sha256` and `signature`); no `antivirus_products:` block
  (`Unsupported`).
- **Every emitted field is declared** (`every_emitted_field_is_declared`, ADR 0026).
- **Rule 9, as a test**: one report with Defender rows found, scanned once with an empty list and once with a
  third-party product `on`. Every Defender row's state, strength, placement and count are identical in both, in
  both modes. Only the statement differs.
- **View**: the statement in Self mode; in SS mode only beside a listed `defender` row; a profile path in it
  redacted; never counted.
- **Baseline**: a new collector needs a `baseline-*` host that reads it (`crates/rongroi-collectors/AGENTS.md`).
  The baselines are rebuilt from a scan of the machines they describe; none is written by hand. Until then a
  rule on this collector gets a `rules/unconfronted.csv` row with its `resolved_when`.
- **Rule fixtures**: only if Owner decisions question 2 adds a rule: positive, `products_on: 0` with Defender
  `off` and a third-party product `off`; negative, a third-party product `on` and Defender `off`. The negative
  is a fixture, not an allowance: the rule matches a count, never a name.
- **Lab replay** (ADR 0076): one scenario on the lab machine, `antivirus_product/defender-only`, expects the
  statement to list one product, `on`, with a valid signature, and expects no Defender row to change. The lab
  machine has Defender only, so it cannot show a second product.

## Order of work

1. **A0, probe** (the development PC, read-only, a counts-and-words probe): the WSC API's list at Medium and at
   High integrity; on the lab machine, whether reading a junction's attributes without following it opens
   any connection to the share it points at (section 3); `RemediationPath` beside WMI's `pathToSignedProductExe` for each product; the time to hash
   and check each file; the list straight after a sign-in; the answer with `wscsvc` stopped, if the owner allows
   stopping it on that PC. Results go into this ADR as "Measured", with no path below a profile and no GUID.
2. **Owner decisions** below, with A0's results.
3. **The collector** (sections 1–4), its tests, the fixture host block, `clippy.toml`, the glossary, the
   privacy and consent texts, a CHANGELOG line. One pull request into `dev`, written by an engineer run.
4. **The statement and the rule text** (section 5): the view, the `defender` tags, the `falsepositives`
   lines, the regenerated rules reference, `docs/coverage.md` by `cargo xtask coverage`, the lab scenario. One
   pull request after step 3.
5. **S11, on a PC with another antivirus (P4)**: the list, Defender's state in it, `service_windefend`, whether
   a 5001 was written, whether the exclusions are still there, and which Defender rules fire. Its results amend
   this ADR, ADR 0059's "What is unverified" and the two rules whose text claims what another antivirus does.
6. Only after step 4 is on a release may a server block on a Defender rule (Q21). That gate is the Server
   Kit's.

## Owner decisions (open)

1. **The source** (section 1). Recommended: **the WSC API** — documented state, no decoding, no WMI.
   Alternative: WMI `root\SecurityCenter2` `AntiVirusProduct`, which gives a named program path but an
   undocumented class and a state number nobody can decode by a published layout (section 2). Decided after A0
   if `RemediationPath` is not a program file.
2. **One `posture` rule**, `rules/antivirus_product/registered/no-product-reports-on`, `match:
   { products_on: 0 }`, `experimental`: "Windows Security Center lists no antivirus product that reports
   itself on". Recommended: **yes** — it is the machine requirement a server would gate on, it counts states and
   names no product, and it keeps ADR 0089's `posture` profile sentence true. Its `falsepositives`: a Windows
   image that removed Defender; a lapsed third-party subscription; an antivirus that does not register with
   Security Center; Security Center not yet updated after sign-in. Its `description` and `falsepositives` also
   say the other side: its `not_found` means only that some registration reports `on`, and **any registration
   that reports `on`, a fake one a program made for itself included, makes it `not_found`**. So a server gate
   that reads this rule learns nothing about what actually protects the PC. Alternative: no rule; the
   statement only.
3. **`display_name` in SS mode** (section 7). Recommended: **shown**. Alternative: withheld like `entry`, so
   SS mode shows only states and signature facts.

## Alternatives weighed

| Alternative | Why not |
|---|---|
| WMI `AntiVirusProduct` | Undocumented class; `productState`'s layout is a community convention; WMI declined three times (ADR 0011, 0038, 0069). Kept as question 1's alternative |
| Decode `productState` by the common convention | States a layout Microsoft never published as fact (section 2) |
| Security Center's registry keys | Undocumented layout, not read for this ADR, and which process writes them is not established |
| `MSFT_MpComputerStatus.AMRunningMode` | No collector reads it; WMI; says what Defender thinks of itself, not what else is registered (section 1) |
| Soften a Defender row when another product is `on` | Vouching (hard rule 9); a registration can be faked (section 5) |
| A list of known antivirus vendors, to mark a product "real" | Vouching (hard rule 9, ADR 0084) |
| A `context` rule found for every listed product | Found on every client PC; noise in SS mode, and no baseline is quiet on it (ADR 0017) |
| Fold the list into `os_image` | Another source and another kind of call; `os_image` reads registry values only |

## What is unverified

- Whether another antivirus makes Defender write a 5001, set `WinDefend` to `disabled`, or drop its
  exclusions (S11, P4).
- Whether `RemediationPath` names the product's program file (A0).
- Whether a standard account can read the list (A0).
- Whether reading a path component's attributes without following a link can reach the network (A0, lab).
- How Security Center checks a program that registers as an antivirus, and so how easily a registration can be
  made by something that is not one.
- What the API answers on a Server edition, and with `wscsvc` stopped (A0 for the second, nobody for the first:
  section 4 does not depend on it).
- Whether Security Center lists nothing for a moment after sign-in (A0).
- How a third-party product's `state` follows its own real-time switch, and how quickly.

## Consequences

- A report says which antivirus products Windows lists and what each says of itself, beside the Defender rows.
  A reviewer can tell "Defender off, nothing else listed" from "Defender off, another product listed `on`"
  without the program telling them which to believe.
- **A listed product is a fact, not a reason.** A cheat may register a fake product that reports `on`
  (section 5). The file facts (`path_kind`, `signature`, `signer`) are there so a reviewer can look at it;
  nothing reads them as trust.
- **The proposed `no-product-reports-on` rule is cleared by any registration that reports `on`**, a
  self-registered fake one included. If a server gates on it, the gate passes a PC on what a program told
  Security Center, not on what protects the PC. The rule's text says so (Owner decisions, question 2).
- A product's file is opened only through ADR 0091's local-drive check (section 3), so a registration cannot
  make this program open a network path through any link the program can see. Some products' files then go unhashed, with
  `file_unread` saying why.
- The meaning of the Defender rows is still not confirmed against a PC with another antivirus. S11 on a P4
  machine is still needed before the claims in `defender-service-disabled` and ADR 0059 can be called measured.
- One new collector, one new `windows` feature, one new kind of cross-source statement, a few banned methods,
  and possibly one `posture` rule. `rongroi-host` and every host implementation gain the source.
