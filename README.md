# nexwall-scripts

Operator/support tooling for the Nexwall Firewall (nftables/`fw4`, based on
NethSecurity/OpenWrt). Each tool lives in its own directory: the executable
script plus a `.md` doc with usage, examples, and known caveats.

## Tools

| Tool | Purpose |
|---|---|
| [`drppkt`](drppkt/drppkt.md) | Live packet trace showing the matched firewall rule (Rule ID) and NAT translation (NAT ID) for traffic to/through the firewall, including the local `input` chain. |
| [`fwtrace`](fwtrace/fwtrace.md) | Same underlying tracer, focused on routed/NAT'd traffic only (`forward`/`dstnat`/`srcnat`), with per-flow deduplication and conntrack-based NAT correlation. Efficient shell/awk implementation (no per-packet interpreter). |

Both are self-contained POSIX `/bin/sh` scripts (tested against BusyBox
`ash` on-device) with no dependencies beyond what already ships on Nexwall:
`nft`, `awk` (GNU awk), `conntrack`, `mkfifo`.

## Install

```sh
scp <tool>/<tool> root@<firewall-ip>:/usr/sbin/<tool>
ssh root@<firewall-ip> chmod +x /usr/sbin/<tool>
```

## Design notes shared by both tools

- **Non-invasive**: both only ever insert non-terminating
  `meta nftrace set 1` probe rules — never a `drop`/`reject`/`accept`. They
  observe firewall decisions, they don't make them.
- **Self-cleaning**: probe rules, background helper processes (`nft monitor
  trace`, the `awk` formatter), and temporary FIFOs are all removed on
  normal exit, Ctrl‑C, or (for `drppkt`) an auto-timeout.
- **Single global probe marker per tool**: don't run two instances of the
  *same* tool at once on one box — the second instance's cleanup can remove
  the first instance's still-in-use rules. Running `drppkt` and `fwtrace`
  simultaneously is fine, since each uses its own marker.

## Repo layout

```
nexwall-scripts/
├── README.md
├── drppkt/
│   ├── drppkt
│   └── drppkt.md
└── fwtrace/
    ├── fwtrace
    └── fwtrace.md
```

Future scripts should follow the same pattern: one directory per tool,
containing the executable and its `.md` doc.
