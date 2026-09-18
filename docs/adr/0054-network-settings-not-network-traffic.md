# ADR 0054 — Network settings, not network traffic

- Status: accepted — the owner decided the four questions below on 2026-09-18 and asked for the
  implementation the same day
- Date: 2026-09-17

## Context

A reviewer asks where a PC sent its traffic, and whether its network was set up to change where the game
connects. This program has no network code (ADR 0003), reads nothing but files and registry values
(ADR 0009, ADR 0011), starts no other program (`crates/rongroi-collectors/AGENTS.md`), and never runs in the
background (README). Within those limits there is no record of **where traffic went** that it can read:

| Source | What it would give | Why it is not read |
|---|---|---|
| SRUM (the System Resource Usage Monitor database) | bytes sent and received per app over roughly the last month, with no destination | Windows keeps the database open; reading it needs a shadow copy or the raw volume, which ADR 0041 rules out, and it would not answer "where" anyway |
| The DNS client cache | names resolved in the last minutes to hours | its enumeration API is not documented, and the documented way is to run `ipconfig`, which this program does not do |
| The live TCP table (`GetExtendedTcpTable`) | connections open at the moment of the scan | a reviewer usually asks for the game to be closed first, so it shows almost nothing that matters, it shows every program's peers, and ADR 0003 would need to be amended to read it |
| The Windows Firewall log | connections the firewall logged | off by default, so on most PCs it holds nothing |
| Capturing packets | what was actually sent | needs a driver or a service that keeps running, which ADR 0003 and the README exclude |

**The owner decided on 2026-09-17 that none of these is read.** The one source of *where* a PC connected
that is within the limits is FiveM's own logs, which name some server endpoints; ADR 0052 puts them in the
full scan, and they get their own ADR.

What the limits do allow is to read the **settings** that decide where traffic goes. A reviewer can use them:
a hosts file that sends a FiveM or Rockstar domain elsewhere, a proxy, or a firewall rule written for FiveM.
This ADR proposes a collector for those settings.

## Measured

On one Windows 11 PC (build 26220), 2026-09-16, with the owner's permission, read-only, printing counts
only:

- the hosts file had 6 lines that are not blank or comments, and none named a `cfx.re`, `fivem.net` or
  `rockstargames.com` host;
- the current user's proxy was off;
- 4 Windows Firewall rules referred to FiveM or FXServer.

How the probe listed the firewall rules was not recorded, and the registry form of a rule was not read.

**Second measurement, 2026-09-17**, same PC, same permission, run once elevated and once with a limited
token (a scheduled task at `HIGHEST` and one at `LIMITED` on the signed-in desktop), printing counts, value
kinds and the shape of a rule with its user name, rule name and description masked. The script and its
output were deleted afterwards. **Both tokens read exactly the same thing**, so none of the three places
needed administrator rights on this build.

| Place | What was read |
|---|---|
| `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters` | a value `DataBasePath`, `REG_EXPAND_SZ`, `%SystemRoot%\System32\drivers\etc` |
| the `hosts` file in that folder | readable; 36 lines, 6 in effect, UTF-8 with a byte-order mark, at most two names per line, no tab; addresses: 1 loopback, 2 private, 3 others; no listed name |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings` | `ProxyEnable` present, `REG_DWORD`, `0`; no `ProxyServer`, `AutoConfigURL`, `ProxyOverride` or `AutoDetect` value. Its `Connections` subkey holds one binary value per connection, named after the connection — VPN products among them |
| `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules` | 909 values, all `REG_SZ`; `Get-NetFirewallRule` listed the same 909, all in the local store. Each value is `v2.<n>` followed by `\|`-separated `key=value` pairs and a trailing `\|`, in seven format versions (`v2.10` to `v2.33`). Keys seen include `Action`, `Active`, `Dir`, `Protocol`, `Profile`, `App`, `Name`, `Desc`, `Svc`, `LPort` and `RA4`; **a key can repeat** (`Profile` twice) |
| the FiveM rules among them | 4, the same 4 `Get-NetFirewallApplicationFilter` found, all `v2.10`, `Action=Allow`, `Active=TRUE`, `Dir=In`, one TCP (`Protocol=6`) and one UDP (`17`) per program, each with a `Defer` key. Two name `...\appdata\local\fivem\fivem.exe`; two name GTA V Enhanced's executable **inside FiveM's own folder** (`...\appdata\local\fivem for gtav enhanced\gamecache\...\gta5_enhanced.exe`). The paths were lower-case and under the user's profile. None of their value names was a GUID |
| firewall rules from Group Policy | `HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules` absent |

What this changes in the proposal:

- `hosts` is found through `DataBasePath`, expanded as `ProfilesDirectory` is (ADR 0049); a value that does
  not expand to a drive-rooted folder is `read_failed`. A byte-order mark is skipped before lines are read.
- `firewall` reads that one key. A rule is FiveM's when its `App` is under a FiveM program folder
  (`%LOCALAPPDATA%\FiveM` or `%LOCALAPPDATA%\FiveM for GTAV Enhanced`), compared without case, because the
  game's executable lives there too. Only `Action`, `Active`, `Dir`, `Protocol`, every `Profile`, and `App`
  are reported; `Name` and `Desc` are not, because a rule a person wrote can say anything. A value that does
  not start with `v2.` is counted as unparsed. Rules from Group Policy or other policy stores are not read in
  this change.
- `proxy` reads the `Internet Settings` values only. `Connections` is not read: its value names name the
  PC's VPN and dial-up connections.

## Decision

### 1. A collector, `net_config`, in the standard tier

It reads three places, told apart by a discriminator `location` (ADR 0044):

- **`hosts`** — the hosts file, found through the folder Windows' TCP/IP parameters name for it, which
  defaults to `%SystemRoot%\System32\drivers\etc` (`DataBasePath`, measured). One observation for the
  file: how many lines are in effect (not blank, not a comment). One observation per line in effect **whose
  host name is, or ends in `.` followed by, a name on a fixed list** (section 2), with that host name and
  the address the line gives it (section 4). Other lines are counted and never reported: they are the
  player's own choices about the rest of the internet.
- **`proxy`** — the current user's `Internet Settings` key: whether `ProxyEnable` is on, and whether a
  `ProxyServer` and an `AutoConfigURL` value exist. **Never their values**: an address can name a person's
  own server or a company's.
- **`firewall`** — Windows Firewall rules for a program in a FiveM folder: whether each is enabled, its
  direction, action, protocol and profiles, and the program path, redacted in SS mode like every path. Where
  the rules are and their form are under "Measured"; a form this program cannot parse is counted as
  unparsed, and a key it cannot read makes the place `read_failed`, not empty.

It needs no administrator rights for any of the three (measured). It opens nothing for
writing, and it reads no value it does not report.

### 2. The fixed list of names

`cfx.re`, `fivem.net` and `rockstargames.com`, with their subdomains. A name joins the list in a change
that says which FiveM or Rockstar service uses it.

### 3. One rule to start

`net_config/hosts/fivem-or-rockstar-name-in-hosts` (`posture`, `experimental`): a line in the hosts file
gives a listed name an address. Its `falsepositives` are ad and telemetry blocklists that point Rockstar
names at `0.0.0.0`, guides that block the launcher's update or sign-in servers, and software that writes its
own entries. The proxy and firewall places have no rule: an enabled proxy and an allowed FiveM program are
what ordinary PCs have. Self mode lists them, and SS mode counts them.

### 4. The address in a hosts line

Reported as written in Self mode, and in SS mode only as its kind — `loopback`, `unspecified`
(`0.0.0.0`, `::`), `private` or `public`. The kind is what separates a blocklist from a redirect; the address
of a redirect can name the player's own server (owner decision 2).

## Alternatives weighed

| Alternative | Why not |
|---|---|
| Read the live TCP table anyway | Shows the moment of the scan, usually with the game closed, and every other program's peers; needs ADR 0003 amended. |
| Report every hosts line | A hosts file is a list of the player's own choices about the whole internet. |
| Report the proxy address | Can name a person's own or employer's server; whether a proxy is on is what a reviewer needs. |
| Put `net_config` in the full scan | The hosts and proxy reads carry no name of a person or server beyond the fixed list; the full tier is for sources that do. |

## What is unverified

- Whether Windows resolves names from the folder `DataBasePath` names when the value is changed. The value
  was read, not changed.
- What `Defer` means and what writes a rule with it — plausibly the Windows prompt that asks to allow a
  program on first use, which was not observed.
- Whether GTA V Legacy under FiveM, or FXServer, gets rules of the same shape. The PC measured had none.
- Whether a standard user can read the firewall key on other Windows builds.
- Whether an ordinary baseline host has any of the listed names in its hosts file, and so whether the rule is
  quiet on `check-baseline`.

## Owner decisions (2026-09-18)

1. The fixed list of names is `cfx.re`, `fivem.net` and `rockstargames.com`, with their subdomains
   (section 2).
2. The address of a hosts line is shown as written in Self mode and only as its kind in SS mode
   (section 4).
3. The firewall place finds FiveM's rules by their program folder and reports only the fields listed under
   "Measured" (section 1).
4. One rule ships, on the hosts place; proxy and firewall have none (section 3).

The points under "What is unverified" stay open; the change that adds the collector says which it
measured.

## Implementation (2026-09-18)

- `net_config` in `rongroi-collectors`, registered in `all()` and after `fivem_dir` in `COLLECTOR_ORDER`.
  Its fields: `location`; for `hosts`, `path`, `present`, `lines_in_effect`, and per listed name `line`,
  `host_name`, `address`, `address_kind`; for `proxy`, `proxy_enabled`, `proxy_server_set`,
  `auto_config_url_set`; for `firewall`, `firewall_rules`, `unparsed_rules`, and per FiveM rule `path`,
  `action`, `enabled`, `direction`, `protocol`, `profiles`. Its reasons are `not_windows`,
  `access_denied` and `read_failed`.
- Choices this ADR left open, made here:
  - A hosts file that is not there is `present: false`, not a gap: Windows reads no line from it.
  - A hosts file starting with a UTF-16 byte-order mark is `read_failed`, because how Windows reads one
    was not measured. Any other bytes are read as UTF-8, with a UTF-8 mark skipped.
  - `address_kind` has a fifth value, `not_an_address`, for text in the address column that is not an
    IPv4 or IPv6 address. The address is parsed in the collector, without `std::net` (AGENTS.md hard
    rule 1); IPv4 link-local counts as `private`, as do IPv6 link-local and unique-local addresses.
  - A name matches the list without ASCII case and without a trailing `.`; a name on a listed line is
    reported as the line spells it.
  - `proxy_enabled` is left out when `ProxyEnable` is absent or not a `REG_DWORD`: how Windows reads either
    was not measured. A missing `Internet Settings` key, or firewall rules key, is `read_failed`.
  - A firewall value that is not text, or larger than the registry bound, counts as unparsed; a `Profile`
    that repeats is kept every time, other repeated keys the first time. Without `%LOCALAPPDATA%` the
    firewall place is `read_failed`, since the FiveM folders cannot be named.
- `rongroi-core::view`: `SS_WITHHELD_FIELDS` removes `net_config`'s `address` from every SS-mode row.
- The rule `net_config/hosts/fivem-or-rockstar-name-in-hosts` matches `location: hosts` and
  `host_name|exists: true`. No baseline can confront it, since every observation carrying `host_name`
  fires it; `rules/unconfronted.csv` says so and what would end the row.
- `baseline-elevated-win11` gains a hosts file, the proxy and firewall rules in the measured shapes with
  invented values; `baseline-consumer-win11` gains the proxy and FiveM's two Legacy rules. A new fixture
  host, `net-config-listed-name`, and its SS-view snapshot show a match without the address.
- The Windows job reads the three places on its runner and prints the file's line count, the proxy flags
  and the rule counts beside `Get-NetFirewallRule`'s, never a line or a rule's name.
- The consent question (CLI and desktop, both languages), `PRIVACY.md`, `docs/architecture.md`, the
  glossary, both READMEs and both screenshare guides name the new reads. The points under "What is
  unverified" stay open.

## Consequences

- `rongroi-collectors`: `net_config`, registered in `all()` and in `COLLECTOR_ORDER`, with fixture hosts
  for each place and for each unreadable place.
- `rongroi-core`: the SS-mode kind of a hosts address in `view`, if decision 2 is taken.
- `rules/net_config/…` with fixtures, Thai text and a baseline check.
- The consent question (CLI and desktop), `PRIVACY.md`, `docs/architecture.md`, the glossary and the desktop's
  collector names say what is read, in the change that adds the collector.
- Fixture hosts built from the shapes measured above with invented values of the same form; no rule value
  measured on a PC is vendored.
