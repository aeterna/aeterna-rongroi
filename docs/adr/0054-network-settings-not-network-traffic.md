# ADR 0054 — Network settings, not network traffic

- Status: proposed
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

## Decision (proposed)

### 1. A collector, `net_config`, in the standard tier

It reads three places, told apart by a discriminator `location` (ADR 0044):

- **`hosts`** — the hosts file, found through the folder Windows' TCP/IP parameters name for it, which
  defaults to `%SystemRoot%\System32\drivers\etc` [the value name is unverified]. One observation for the
  file: how many lines are in effect (not blank, not a comment). One observation per line in effect **whose
  host name is, or ends in `.` followed by, a name on a fixed list** (section 2), with that host name and
  the address the line gives it (section 4). Other lines are counted and never reported: they are the
  player's own choices about the rest of the internet.
- **`proxy`** — the current user's `Internet Settings` key: whether `ProxyEnable` is on, and whether a
  `ProxyServer` and an `AutoConfigURL` value exist. **Never their values**: an address can name a person's
  own server or a company's.
- **`firewall`** — Windows Firewall rules whose program path is a FiveM or FXServer executable: whether each
  is enabled, its direction and its action, and the program path, redacted in SS mode like every path. The
  place Windows keeps rules in the registry and the form of a rule must be measured before this is written
  [unverified]; a form this program cannot parse makes the place `read_failed`, not empty.

It needs no administrator rights for `hosts` and `proxy` [to measure for `firewall`]. It opens nothing for
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

Proposed: reported as written in Self mode, and in SS mode only as its kind — `loopback`, `unspecified`
(`0.0.0.0`, `::`), `private` or `public`. The kind is what separates a blocklist from a redirect; the address
of a redirect can name the player's own server. This is an owner decision below.

## Alternatives weighed

| Alternative | Why not |
|---|---|
| Read the live TCP table anyway | Shows the moment of the scan, usually with the game closed, and every other program's peers; needs ADR 0003 amended. |
| Report every hosts line | A hosts file is a list of the player's own choices about the whole internet. |
| Report the proxy address | Can name a person's own or employer's server; whether a proxy is on is what a reviewer needs. |
| Put `net_config` in the full scan | The hosts and proxy reads carry no name of a person or server beyond the fixed list; the full tier is for sources that do. |

## What is unverified

- The registry value that names the hosts file's folder, and whether Windows reads the file from there on
  current builds.
- Where Windows Firewall keeps its rules in the registry, the form of one rule, and whether a standard user
  can read them.
- Whether an ordinary baseline host has any of the listed names in its hosts file, and so whether the rule is
  quiet on `check-baseline`.

## Owner decisions this ADR needs

1. The fixed list of names (section 2).
2. The address of a hosts line: shown in Self mode and only as a kind in SS mode (section 4).
3. The firewall place, with its fields, once its form is measured (section 1).
4. The one rule, and no rule for proxy and firewall (section 3).

## Consequences

- `rongroi-collectors`: `net_config`, registered in `all()` and in `COLLECTOR_ORDER`, with fixture hosts
  for each place and for each unreadable place.
- `rongroi-core`: the SS-mode kind of a hosts address in `view`, if decision 2 is taken.
- `rules/net_config/…` with fixtures, Thai text and a baseline check.
- The consent question (CLI and desktop), `PRIVACY.md`, `docs/architecture.md`, the glossary and the desktop's
  collector names say what is read, in the change that adds the collector.
- A measurement on a real Windows PC, with permission, before the `firewall` place is written.
