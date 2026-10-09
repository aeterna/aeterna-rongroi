# ADR 0065 — Websites known to hand out loaders, as hashes

- Status: accepted — the owner decided the six questions below on 2026-10-09, each as recommended; not
  implemented until the first row exists (section 4)
- Date: 2026-10-09

## Context

ADR 0064 reads which kinds of words PowerShell's commands held and keeps one piece of text: the host of the
first URL a command downloads from (`download_host`), shown in SS mode only after its own question. What a
`found` download-then-execute row cannot say is whether that host is an installer's or a cheat seller's —
and on the one development PC measured, all three such lines were installers (ADR 0064, "Measured before
code"). A reviewer is left asking the player.

Some hosts serve nothing but a cheat's loader. A seller's own instructions name them, in a video or on a sales
page, because the buyer has to type the line. A list of those hosts, shipped in the rules bundle and matched
offline, would turn "a command downloaded something and ran it" into "a command downloaded from a website
listed as handing out a loader" for those hosts, and say nothing about any other.

The owner decided in the PowerShell plan (D6, 2026-10-08) that such a list holds **SHA-256 hashes of hosts,
not the hosts**, so the repository is not a directory of cheat sellers. ADR 0064 §6 named this as a later ADR.

### What already exists

- **`match_lists`** (ADR 0048): a rule names a data file beside `rule.yaml`; the bundle loader expands its first
  column into a list under `match`, and the engine is unchanged. `cargo xtask rules-reference` renders the
  condition as the file's name and row count, never its values. The LOLDrivers list is the one user today.
- **Its limits**, read from `crates/rongroi-core/src/rules.rs`: the file must have **at least one row**; its
  first column is checked as lowercase hex only when the field is named `sha256`.
- **`download_host`**: lower-cased, host only — no scheme, user, password, port, path or query (ADR 0064 §4).
  An address is kept as `download_address_kind` and is not a host. An internationalised name is kept as
  written in the command, not converted to its `xn--` form (not measured either way).

## Decision

### 1. A hashed host beside the host

`powershell_text` adds `download_host_sha256` to every group that carries `download_host`: the SHA-256 of the
host's UTF-8 bytes, lowercase hex, after removing one trailing dot. It is declared sensitive with the same kind,
`SensitiveKind::DownloadHost`, so SS mode shows `%DOWNLOAD_HOST%` in its place unless the player agreed to show
websites. A hash of a host is not anonymous: anyone can hash a guessed name and compare, so showing it would undo
the question ADR 0064 §4 asks.

No hash is made for an address. A seller who serves from an address is not listed by this ADR.

### 2. One data file, hashes and a reason, no names

`rules/powershell_text/known-loader-host/known-loader-hosts.csv`, one row per host:

| Column | Holds |
|---|---|
| `download_host_sha256` | the hash of section 1 |
| `added` | the date the row was added |
| `seen_in` | one of `sales_page`, `video`, `instructions`, `server_report` — where the host was seen handing out a loader |
| `note` | a sentence with no host, no seller's name, no product name and no link |

The host, the seller and the evidence itself stay out of the repository. The evidence is checked by the
maintainer who merges the row (section 4) and kept outside it; the pull request says that it was, never what it
was. `match_lists` reads only the first column.

`rules.rs` checks the first column as lowercase hex for any field whose name ends in `_sha256`, not only
`sha256`, so a typo cannot ship a row that matches nothing.

### 3. Rules: one per source

`powershell_text/{history,engine-start,script-block}/known-loader-host`, `strength: presence`, `status:
experimental`, `match: {source: …}`, `match_lists: {download_host_sha256: ../known-loader-hosts.csv}` — or the
file copied beside each rule if `match_lists` keeps requiring a file beside `rule.yaml` (to be settled in the
code change; one source of truth either way). One per source for the reason ADR 0064's rules are (its "As built"
item 1, ADR 0044). `script_block` gets a rule here although ADR 0064 gave it none: a listed host is specific
where a kind of word is not.

The match does not require `download_then_execute`: a listed host is the evidence, however the command used it.
`unmeasured_when: [not_windows, source_absent]`. `description` says the row means a command named a host on
this list, not that it ran, worked or was a cheat; `falsepositives` say a seller can host other files, a host
can change hands, a list entry can be wrong, and a missing row means nothing — a seller changes domains faster
than this project releases.

### 4. Who adds a row, and on what

- A row is added by a pull request reviewed by a maintainer, who checks the evidence privately against
  `seen_in` before merging. A row is never added from one player's report alone: `server_report` means a server
  team saw the host in a seller's own instructions handed to a player, and the maintainer saw those
  instructions.
- **Never listed**: a host that serves anyone's files — a code host, a paste site, a file-sharing service, a
  chat platform's attachments, a CDN, a URL shortener — whatever a seller put there. Listing one would make the
  row say "a player downloaded from GitHub". The rule's description says so, and so does the file's header.
- A row is removed by the same kind of pull request when the host changes hands or the evidence turns out wrong.
- **The rule ships only with its first row**, because `match_lists` refuses an empty file and an empty list
  would be a rule that can never be `found`, read as a check that was made. Until a row exists, this ADR changes
  nothing a player sees.

### 5. What a reader sees

A `found` row: "A command in the PowerShell history downloaded from a website on this project's list of
websites that hand out cheat loaders", with `count`, the kinds, and in SS mode `%DOWNLOAD_HOST%` unless agreed.
As for LOLDrivers (ADR 0048), the reader who wants to know which row matched asks the player to show the
website, or searches the file for the hash in Self mode; the `seen_in` and `note` columns are on that line.

### 6. What this ADR does not do

- No suffix matching. `a.seller.example` does not match a row for `seller.example`; each host is listed.
  Matching every suffix would need a public-suffix list to know where a registrable name begins, or would match
  a whole platform's hosts.
- No address list, no file-hash list of loaders, no list of hosts outside PowerShell (a browser's history is
  never read, ADR 0052 §5).
- No update outside a release. The program fetches nothing (ADR 0003).

## Before any code

1. **The first row**, with its evidence checked by the owner. Without it there is nothing to ship (section 4).
2. On the development PC (counts only): how many `download_host` values the history, the flagged blocks and the
   engine starts hold, and that the first row's hash matches none of them — the three installer lines measured in
   ADR 0064 must stay quiet.

   Half of item 2 is in hand from ADR 0064's release-build full scan of 2026-10-08: groups are keyed by host,
   and the development PC's history held two groups with a `download_host` (one of three download-then-execute
   lines, one of a download alone), so two distinct hosts at most; its flagged blocks and engine starts held
   none. Whether the first row matches either is checked when the row exists.

## Alternatives weighed

| Alternative | Why not |
|---|---|
| Hosts in clear text | The repository would list where to buy cheats, which the owner ruled out (D6). |
| A keyed hash (HMAC) with a key in the binary | The key is in an open-source binary; it hides nothing from anyone who wants to check a name, and makes the list impossible to review. |
| Match the registrable domain | Needs the public-suffix list bundled and kept current, and turns one row into every host under a name (section 6). |
| A list per release in a separate download | The rules bundle is already the versioned, hashed, offline data carrier (ADR 0048); a second one is a second thing to verify. |
| Fetch the list at scan time | Network code (ADR 0003). |
| Wait for a seller name list (ADR 0064 §6) | Names change weekly and advertise; a host is what the command holds. |

## What is unverified

- Whether sellers' hosts last long enough between releases for a row to ever match. Nothing has been measured;
  the rule's own text says a missing row means nothing.
- How PowerShell writes an internationalised host on the command line, and whether two spellings of one
  name reach the same hash.
- Whether a hashed list is any obstacle to someone who wants the names: a seller's host is public by
  definition, so a dictionary of candidates is easy. The hash keeps the repository from being the directory; it
  does not keep the names secret, and the ADR does not claim it does.

## Owner decisions (2026-10-09)

The owner answered "as recommended" to all six, question 1's channel included: the private reporting
`SECURITY.md` describes carries evidence for a row.


1. **Ship the mechanism only with a first row** (section 4), and the first row comes from evidence the owner
   checks. Recommended.
2. `download_host_sha256` **sensitive like the host** (section 1). Recommended: otherwise a hash of a private
   name could be guessed back in SS mode.
3. The file's columns, with no host, seller or link in the repository (section 2). Recommended.
4. **Never list a shared platform** (section 4), even when a seller uses one. Recommended.
5. Three rules, one per source, `presence`, not requiring `download_then_execute` (section 3). Recommended.
6. Exact hosts only, no suffix matching (section 6). Recommended.

## Consequences (if accepted)

- `rongroi-collectors::powershell_text`: `download_host_sha256`, sensitive; its tests and snapshots.
- `rongroi-core::rules`: the `_sha256` check for any such field; its test.
- `rules/powershell_text/known-loader-host/`: the data file with its first row and a header saying what is never
  listed, a `PROVENANCE.md` saying how rows are added and removed (not where each came from), three rules with
  fixtures — a positive fixture whose hash is a synthetic host's under `.invalid`, which the real file never
  holds, so the fixture needs its own one-row file or the rule its test-only list (to be settled in the code
  change) — Thai translations, `unconfronted.csv` rows.
- `CONTRIBUTING.md`: how to propose a row, and that the evidence goes to a maintainer privately, never in the
  pull request. The private reporting `SECURITY.md` describes is the channel in place today; it was set up for
  bypass reports, so using it for this is part of owner question 1.
- `docs/architecture.md`, the screenshare guides (what a row means, what it does not), `PRIVACY.md` (a hash of
  the host, sensitive like the host), CHANGELOG.
