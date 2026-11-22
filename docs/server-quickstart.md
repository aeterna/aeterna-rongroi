# Rongroi on your server: quickstart

For a server owner who wants players to send a PC check to staff with **Rongroi Connect**. Rongroi shows evidence for
your staff to read. It never says a PC is clean and never kicks or bans anyone (ADR 0002).

Thai: [server-quickstart.th.md](server-quickstart.th.md) · Design: [ADR 0097](adr/0097-easy-adoption-relay-and-rr2.md)

## Choose how reports reach you

| | Direct | Rongroi Relay |
|---|---|---|
| Extra machine or container | none | one small container you run (HTTPS) |
| Your game port must accept plain HTTP from players | yes | no |
| Works behind the Cfx proxy | no | yes |
| Report size | chunks of 4 KiB (Enhanced limit) | one upload, up to 2 MiB |
| Pairing code | `rr1.` | `rr2.` (needs Connect 0.2 or newer) |

AETERNA runs no relay for you. A relay is yours, like your game server.

## FiveM: direct (about 10 minutes)

1. Copy `nakara_rongroi` from the latest
   [nakara-oss release](https://github.com/aeterna/nakara-oss/releases?q=nakara_rongroi) into `resources/`.
   Keep the folder name `nakara_rongroi`.
2. In `server.cfg`:
   ```
   ensure nakara_rongroi
   add_ace group.admin nakara_rongroi.staff allow
   set rongroi_public_origin "http://<your public IP or name>:<game port>"
   set rongroi_server_name "<your server name>"
   ```
   Use `set`, never `setr`. Players see the server name in Connect before they agree. Without
   `rongroi_server_name` the Kit uses `sv_projectName`; staff can change the name on the panel's Policy screen.
3. Start the server and run `rongroi doctor` in the console. Each line says `ok` or `FAIL` with the reason.
4. In game, staff type `/rongroi`, enter the player's server id and press **Open case**. The panel shows a pairing
   code; the player pastes it into Connect (or the launcher).

## FiveM: with a Rongroi Relay

1. Run the relay: [nakara-oss `relay/`](https://github.com/aeterna/nakara-oss/tree/dev/relay) has a Dockerfile, a
   Compose file with Caddy for HTTPS, and `node main.js keygen <server-id>`, which prints the lines for step 2.
2. In `server.cfg`, instead of `rongroi_public_origin`:
   ```
   ensure nakara_rongroi
   add_ace group.admin nakara_rongroi.staff allow
   set rongroi_relay_url "https://relay.example.org"
   set rongroi_relay_id "my-server"
   set rongroi_relay_key "<from keygen>"
   set rongroi_server_name "<your server name>"
   ```
3. `rongroi doctor` checks that the relay answers and that the key is the one for `my-server`.

Any resource on your server can read a `set` convar; run only resources you trust.

## Not FiveM

Run a relay, and on your server use
[`@aeterna_game/rongroi-envelope`](https://github.com/aeterna/nakara-oss/tree/dev/sdk/rongroi-envelope) to open the
reports your server pulls from it. The protocol is ADR 0097 §3; the test vectors are in the SDK. Show what you receive
to staff as evidence; do not turn it into a pass or fail.

## Updating the Kit

Replace the folder **but keep `cache/rongroi-reports/`**: on FXServer Enhanced the stored reports live there. If the
folder was replaced anyway, the Kit says so at start (`stored reports missing: expected <n>, found <m>`) and staff see a
banner; the reports cannot be recovered from the server.

## Which versions work together

| Server Kit `nakara_rongroi` | Rongroi Connect | Relay | Codes | Envelope |
|---|---|---|---|---|
| 0.1.x | 0.1.x and newer | — | `rr1.` | v1 |
| 0.2.x, direct | 0.1.x and newer | — | `rr1.` | v1 |
| 0.2.x, relay | **0.2.x and newer** | 0.1.x | `rr2.` | v2 |

Connect checks every report itself before sending; the scanner it bundles (`rongroi-scan`) follows Connect's release.
