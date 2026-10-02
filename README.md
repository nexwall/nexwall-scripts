# nexwall-scripts

Operator/support tooling for the Nexwall Firewall (nftables/`fw4`, based on
NethSecurity/OpenWrt). Each tool lives in its own directory: the executable
script plus a `.md` doc with usage, examples, and known caveats.

## Tools

| Tool | Purpose |
|---|---|
| [`drppkt`](drppkt/drppkt.md) | Per-flow decision with the deciding rule's name, the reason (firewall rule, zone policy, DPI, IP & Geo Blocking) and the full rule path, including traffic to the firewall itself (`input` chain). |
| [`fwtrace`](fwtrace/fwtrace.md) | Same engine, focused on routed/NAT'd traffic, one line per flow and decision, with conntrack-based NAT correlation. |
| [`nfq-watchdog`](nfq-watchdog/nfq-watchdog.md) | Recovers the DPI / IPS engines when a kernel packet queue stops being served: diagnostics report, optional core dump, alert, restart with limits. Runs from cron. `analyze-core` reads the dumps. |
| [`dpidbg`](dpidbg/dpidbg.md) | Look inside the DPI engine: status, unclassified traffic, loaded catalog, debug capture with summary. |

`drppkt`, `fwtrace`, `nfq-watchdog` and `dpidbg` are POSIX `/bin/sh` scripts (tested against BusyBox `ash` on-device) sharing `lib/trace.awk` and `lib/common.sh`
(installed under `/usr/lib/nexwall-scripts`). Dependencies: `nft`, GNU `awk` (`gawk`), `conntrack`, `mkfifo`.

## Install

```sh
# normally shipped by the nexwall-scripts package; by hand:
scp fwtrace/fwtrace drppkt/drppkt root@<firewall-ip>:/usr/sbin/
ssh root@<firewall-ip> mkdir -p /usr/lib/nexwall-scripts
scp lib/trace.awk lib/common.sh root@<firewall-ip>:/usr/lib/nexwall-scripts/
ssh root@<firewall-ip> chmod +x /usr/sbin/fwtrace /usr/sbin/drppkt
```

## Design notes shared by both tools

- **Non-invasive**: both only ever insert non-terminating
  `meta nftrace set 1` probe rules — never a `drop`/`reject`/`accept`. They
  observe firewall decisions, they don't make them.
- **Self-cleaning**: probe rules, background helper processes (`nft monitor
  trace`, the `awk` formatter), and temporary FIFOs are all removed on
  normal exit, Ctrl‑C, or (for `drppkt`) an auto-timeout.
- **Unique marker per run**: several traces can run at the same time; each removes only its own probes.
- **Validated input**: filters are checked (addresses, ports, `tcp|udp|icmp|icmpv6`) before they reach `nft`, because
  the Log Viewer's API passes user-entered filters to these tools.

## Repo layout

```
nexwall-scripts/
├── README.md
├── lib/
│   ├── trace.awk
│   └── common.sh
├── docs/
│   ├── kba-dpi-engine-stall.md
│   ├── kba-unknown-applications.md
│   ├── kba-fast-path-offload.md
│   ├── kba-dpi-ips-tuning.md
│   └── watchdog-logs-and-coredumps.md
├── drppkt/
├── dpidbg/
├── fwtrace/
├── nexwall-fastpath/
├── perf-bench/
└── nfq-watchdog/
```

## Knowledge base articles

- [`docs/kba-dpi-engine-stall.md`](docs/kba-dpi-engine-stall.md): new connections hang while the firewall looks healthy.
- [`docs/kba-unknown-applications.md`](docs/kba-unknown-applications.md): traffic shows as Unknown or an application is not blocked.
- [`docs/kba-fast-path-offload.md`](docs/kba-fast-path-offload.md): the fast path (flow offload): commands, status, where offloaded traffic shows, troubleshooting.
- [`docs/kba-dpi-ips-tuning.md`](docs/kba-dpi-ips-tuning.md): the tuning controls in the DPI and IPS Settings tabs, what they do, how to check the effect.
- [`docs/watchdog-logs-and-coredumps.md`](docs/watchdog-logs-and-coredumps.md): where the queue watchdog logs, reports and core dumps are, and how to enable core dumps.

Future scripts should follow the same pattern: one directory per tool,
containing the executable and its `.md` doc.
