# `drppkt` - "why was this packet dropped or allowed?"

**Applies to:** Nexwall Firewall 26.0.0-rc1 (nftables / `fw4`)  ·  **Location:** `/usr/sbin/drppkt`

Same engine as `fwtrace` (see `fwtrace.md` for the reasons table, filter tokens and options), with two differences:

1. it also hooks the **`input`** chain, so it covers traffic addressed to the firewall itself (SSH, the web UI, VPN
   ports...);
2. it prints, under each decision, **every named rule the packet crossed** (`-j` adds the same list as a `path`
   array).

```sh
drppkt --both src host 192.168.1.102 -i 30
drppkt dst host 192.168.1.1 and dst port 443
```
```
TIME     PROTO SRC                    DST                    ACTION  RULE                           REASON
01:48:48 tcp   192.168.1.102:42940    57.144.66.1:443        REJECT  (dpi_actions)                  DPI: application or protocol blocked by policy
         prerouting             jump     Handle lan IPv4/IPv6 helper assignment
         dpi_actions            REJECT   ct label "netify-blocked" counter reject
```

## Reading the "Rule" column

The rule's **name** is the `comment` fw4 writes from the UCI rule name (`!fw4: ` stripped). Rules created by
other components have no name (DPI, banIP, IPS): the chain is shown in brackets and the reason column says which
component decided.

## The kernel log lines

The console lines such as `reject wan in: IN=eth1 ... MAC=... SRC=...`, `DPI block: ...` and
`banIP/inbound/drop/<list>: ...` are written by the firewall's own `log` rules, and their **prefix is the reason**:

| Prefix | Meaning |
|---|---|
| `<rule name>: ` | a rule with logging turned on logs under its own name |
| `reject wan in` / `drop wan invalid ct state` | zone policy on that zone and direction |
| `banIP/<inbound\|outbound>/<drop\|reject>/<list>` | IP & Geo Blocking list that matched |
| `DPI block` | DPI blocked the flow |

The Log Viewer turns these prefixes into the same plain-language reasons and has a *trace* link on every row that
opens `fwtrace` for that exact flow to show the rule.

## Safety

Observe-only (`meta nftrace set 1`), removed on exit/`SIGTERM`/`-i`, unique marker per run, validated filter
input, `drppkt --cleanup` after an unclean kill.
