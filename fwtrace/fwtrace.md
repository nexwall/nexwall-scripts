# `fwtrace` - real-time firewall rule & NAT tracer

**Applies to:** Nexwall Firewall 26.0.0-rc1 (nftables / `fw4`)  ·  **Location:** `/usr/sbin/fwtrace`

## What it answers

For each **routed / NAT'd** flow: *was it allowed or blocked, by which rule (its name), and why?* - plus the
NAT translation that was applied. Built on nftables' own tracer (`nft monitor trace`); it never inspects payloads.

The reason covers everything that can stop or pass a packet on the box, not only `fw4`:

| Reason shown | Comes from |
|---|---|
| `Firewall rule: <name>` | a rule in a zone chain (the rule's UCI name) |
| `Zone policy: reject wan IPv4/IPv6 traffic` | the zone's default policy (no rule allowed it) |
| `DPI: application or protocol blocked by policy` | the `dpi_actions` chain (netifyd label `netify-blocked`) |
| `IP & Geo Blocking: matched list <list>` | table `banIP` |
| `Invalid connection state` | `ct state invalid` |
| `Established or related connection` | `Handle forwarded flows` |

## Usage

```sh
fwtrace [options] <filter...>
fwtrace --cleanup
```

Filter tokens (join with `and`): `host <ip>` · `src host <ip>` · `net <cidr>` · `src net <cidr>` · `port <n>` ·
`src port <n>` · `proto <tcp|udp|icmp|icmpv6>`. Unqualified `host`/`net`/`port` = destination. IPv4 and IPv6.

| Option | Effect |
|---|---|
| `-b`, `--both` | also trace the **reverse direction**. Recommended: a DPI or IP-blocking verdict is often applied to the return packets |
| `-i SECS` | stop by itself after SECS seconds |
| `-j` | one JSON object per line (this is what the Log Viewer uses) |
| `--cleanup` | remove leftover probe rules and exit |

```sh
fwtrace --both src host 192.168.1.102 and dst port 443 -i 30
```
```
TIME     PROTO SRC                    DST                    ACTION  RULE                           REASON
01:47:16 tcp   192.168.1.102:49176    57.144.66.1:443        ACCEPT  accept wan IPv4/IPv6 traffic   Zone policy: accept wan IPv4/IPv6 traffic
         NAT: masqueraded: 192.168.1.102:49176 seen upstream, reply routed via 192.168.0.136
01:47:16 tcp   192.168.1.102:49176    57.144.66.1:443        REJECT  (dpi_actions)                  DPI: application or protocol blocked by policy
```
A flow prints once per distinct decision (a new line appears when the decision changes, e.g. accepted, then
rejected by DPI once the application is identified).

## Design notes

- **Non-invasive.** The probe is a non-terminating `meta nftrace set 1` rule. It is removed on exit, on Ctrl-C, on
  `SIGTERM`, and when `-i` expires. Each run has a unique marker, so several can run at once.
- **Hooked chains:** `prerouting`, `forward`, `dstnat`, `srcnat`. `prerouting` matters: NAT chains only see the
  *first* packet of a connection, and the DPI chain runs in prerouting, so without it a DPI reject on an
  established flow is never traced.
- **Input is validated.** The filter becomes part of an nft rule, so only plain addresses, ports and
  `tcp|udp|icmp|icmpv6` are accepted; anything else is refused (`fwtrace host '1.2.3.4; ...'` -> `invalid host`).
- **Engine:** `lib/trace.awk` (shared with `drppkt`), helpers in `lib/common.sh`; requires GNU awk (`gawk`).
- Traffic addressed to the firewall itself is not covered here: use `drppkt`.

## Caveats

NAT lines appear only for new connections (netfilter evaluates NAT once). Ctrl-C does not reach a script started
with `&` from another script: use `-i` or `kill -TERM`. After an unclean kill, `fwtrace --cleanup`.
