# FiveM name in the hosts file

## What the trace stands for

A line in the hosts file that gives `fivem.net` the address `127.0.0.1`. Windows uses the address a hosts line
gives a name instead of asking a DNS server for it, so this line sends `fivem.net` to the PC's own loopback
address. It is the shape a hosts entry that redirects a FiveM name takes. `fivem.net` is one of the three names
the collector lists, with their subdomains: `cfx.re`, `fivem.net` and `rockstargames.com`
(`LISTED_NAMES` in `crates/rongroi-collectors/src/net_config.rs`).

## What the scenario shows

The `net_config` collector reads the hosts file in the folder `DataBasePath` names, which defaults to
`%SystemRoot%\System32\drivers\etc`, and reports the one line in effect that names a listed host. The rule
`net_config/hosts/fivem-or-rockstar-name-in-hosts` reads `found`. In SS mode the row shows the address's kind,
`loopback`, and withholds the address itself. The scenario names no neighbour that must stay `not_found`.

## What the scenario does not show

- Who wrote the line, when, or why. The rule's own falsepositives are ad, tracking and telemetry blocklists that
  point Rockstar names at `127.0.0.1` or `0.0.0.0`, guides that block the launcher's servers by editing the hosts
  file, and software that writes its own entries, such as a VPN or a security suite. A loopback line of this shape
  is the same to the rule whichever of these wrote it.
- Whether any program used the name or the address. The scenario starts no program and makes no connection.
- The other two listed names, `cfx.re` and `rockstargames.com`, and subdomains. Only `fivem.net` is set.
- A hosts file in a folder other than the default. The setup writes to `%SystemRoot%\System32\drivers\etc`.

See [ADR 0076](../../../../docs/adr/0076-lab-replay.md) and
[ADR 0054](../../../../docs/adr/0054-network-settings-not-network-traffic.md).
