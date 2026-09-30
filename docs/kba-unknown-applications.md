# KBA: Traffic shows as "Unknown" or an application is not blocked by Application Control (DPI)

**Product:** Nexwall Firewall 26.0.0-rc1 and later  ·  **Component:** Application Control (DPI), application catalog

## Symptoms

- Monitor > Live flows, or the Application Control rules, show many flows with application "Unknown" (only the protocol,
  for example `HTTPS` or `DNS`, is shown).
- A rule that blocks an application does not stop a service you expected it to stop.
- The share of unknown traffic is high right after the trial ended.

## How the firewall decides which application a flow belongs to

The DPI engine reads the **name** a connection uses (the TLS server name, the DNS name the client looked up, or a hint
learned from earlier DNS answers) and looks it up in the **application catalog**: domain rules (`cnn.com` also covers
`edition.cnn.com`), network rules and a few protocol rules. No rule, no application: the flow keeps only its protocol.
Encrypted connections with no readable name (ICMP, raw IP, some QUIC/VPN traffic) can only be matched by network.

So "Unknown" almost always means **the catalog has no rule for that name**, not that the engine failed.

## Check (2 minutes)

1. **Which catalog is in use?** Application Control (DPI) > Settings shows the source: the **Nexwall catalog** (about 1,500
   applications) or the **built-in list** (199 applications). On the CLI: `nexwall-dpi-catalog status`.
   - `source: open` and license `trial` or `subscribed`: the catalog is not installed yet. Press **Update now**, or read
     `last_error` in the status (no route to the license server? unit not registered yet?).
   - `source: open` and license `unlicensed`: the trial ended and no subscription is active; the built-in list is in use by
     design. Activating a subscription restores the catalog automatically within about 10 minutes.
2. **What exactly is unknown?**
   ```sh
   dpidbg unknown -n 30
   ```
   Lists the share of unknown flows and bytes and the top hosts behind them, and how many unknown flows have no name at all.
3. **Need the detail of a client?** A short debug capture (pauses inspection while it runs, use a maintenance window):
   ```sh
   dpidbg capture -s 45 -i <client ip>
   ```
   The last section, "protocol-only flows by host", is the list of names to add to the catalog.

## Resolution

| Finding | What to do |
|---|---|
| Built-in list in use although licensed | Application Control (DPI) > Settings > **Update now**; check the error shown |
| Trial ended, no subscription | Activate a subscription (Administration > Licensing) |
| Catalog installed, a service still unknown | Send the host names from `dpidbg capture` to support; they are added to the catalog (curated additions are published with the next catalog version) |
| Flows with no name | Expected for ICMP and raw IP traffic; block by network with a firewall rule or an object instead |
| A block rule does not stop an app | The service may be served from a CDN that is classified as its own application (for example a video site whose media comes from Fastly); add a rule for that application too, or check in Live flows which application the blocked-looking flows have |

## Settings

Application Control (DPI) > Settings: automatic update on/off and the check frequency (hourly to weekly). Turning automatic
updates off keeps the current catalog until you press Update now, **except** that a catalog the license no longer covers is
always replaced by the built-in list.

## Notes

- Changing a DPI rule takes effect within seconds (the engine reloads the rules; no restart). A connection that was already
  blocked stays blocked until it ends, even if the rule is removed.
- After a firmware upgrade the catalog is reinstalled automatically.
- Tools: [`dpidbg`](../dpidbg/dpidbg.md). Related: [`kba-dpi-engine-stall.md`](kba-dpi-engine-stall.md).
