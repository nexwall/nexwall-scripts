# `fwtrace` — Real-Time Firewall Rule & NAT Tracer for Nexwall

**Applies to:** Nexwall Firewall 26.0.0-rc1 (nftables / `fw4` backend)
**Location:** `/usr/sbin/fwtrace`
**Status:** shell/awk implementation, replacing an earlier Python version.
Every behavior described below has been tested live against a running unit.

---

## What it does

`fwtrace` watches routed/NAT'd traffic in real time and tells you, per
connection, **which firewall rule decided its fate** and **what NAT
translation (if any) was applied to it** — correlated against the live
conntrack table. It's built entirely on nftables' own packet tracer
(`nft monitor trace`); it doesn't run a packet capture or inspect payloads.

It answers questions like:
- "Is this LAN host's traffic to this destination being allowed or blocked, and by which rule?"
- "Is outbound traffic actually getting masqueraded onto the WAN IP?"
- "Is a port-forward (DNAT) rule actually rewriting the destination the way I configured it?"

It does **not** watch traffic destined to the firewall's own management
interface (SSH, the UI, etc.) — see [Hooked chains](#hooked-chains) below.
For that case, see `drppkt` (in the sibling `drppkt/` folder of this repo),
which also hooks `input`.

---

## Why it's a shell script now, not Python

The original version was a Python script that, per traced packet, spawned a
`subprocess.run(..., shell=True)` for `nft` commands and — for every single
terminal verdict on a NAT hop — re-ran and re-parsed the *entire*
`conntrack -L` table from a fresh process. That's a new process (and on
this platform, a fairly heavy CPython startup) on the hot path for every
matched connection.

This version does the equivalent work inside **one long-lived `awk`
process** reading a continuous stream from `nft monitor trace`:
- No interpreter startup per event — `awk` is already running and just
  processes each line as it arrives.
- `conntrack -L` is still shelled out to for NAT correlation (there's no way
  around asking the kernel for that table), but only when a flow actually
  hits a NAT hop for the *first* time — same frequency as the original, just
  without a Python process in front of it.
- Rule insertion/cleanup (`nft insert`, `nft delete`) still happens via
  plain shell/`nft` calls, which is what the original did too — that part
  wasn't the inefficiency.

Net effect: the cost of running `fwtrace` scales with actual matched
traffic and NAT lookups, not with a per-packet interpreter spin-up.

---

## Usage

```sh
fwtrace [options] <filter...>
fwtrace --cleanup
```

### Filter tokens (join multiple with `and`)

| Token | Matches |
|---|---|
| `host <ip>` | destination address |
| `src host <ip>` | source address |
| `dst host <ip>` | destination address |
| `net <cidr>` | destination network |
| `src net <cidr>` | source network |
| `dst net <cidr>` | destination network |
| `port <n>` | destination port |
| `src port <n>` | source port |
| `dst port <n>` | destination port |
| `proto <tcp\|udp\|icmp>` | restrict to a protocol |

An unqualified `host`/`net`/`port` matches as the **destination**. Use the
explicit `src ...` form for the other direction.

### Options

| Option | Effect |
|---|---|
| `--cleanup` | Remove any leftover probe rules (e.g. after a killed/crashed run) and exit — doesn't start a trace. |
| `-h`, `--help` | Show usage. |

### Examples

```sh
fwtrace host 192.168.1.242
fwtrace src host 192.168.1.242 and dst host 8.8.8.8
fwtrace dst host 192.168.1.242 and dst port 443 and proto tcp
fwtrace dst port 22 and proto tcp
fwtrace net 192.168.1.0/24
fwtrace --cleanup
```

### Sample output

```
[fwtrace] filter: meta l4proto tcp ip daddr 192.168.1.242 th dport 443
[fwtrace] tracing on chains: forward dstnat srcnat (Ctrl-C to stop)
TIME         PROTO SRC                   DST                   CHAIN          RULE                             VERDICT
14:02:11     tcp   192.168.1.50:51500    192.168.1.242:443     forward_lan    Accept-LAN-to-DMZ                ACCEPT
14:02:11     tcp   192.168.1.50:51500    192.168.1.242:443     srcnat_wan     (default policy)                 ACCEPT
             NAT: masqueraded: 192.168.1.50:51500 seen upstream, reply routed via 203.0.113.9
```
Ctrl‑C to stop — this removes the probe rules, kills the background helper
processes, and deletes the temporary FIFO automatically.

---

## Hooked chains

`fwtrace` inserts its trace probe at the top of three chains:

| Chain | Why |
|---|---|
| `forward` | The main "is this routed traffic passing or not" decision point — LAN↔WAN, LAN↔DMZ, etc. |
| `dstnat` | Destination NAT (port forwards) — evaluated in `prerouting`, before the routing decision, so it also fires for new connections destined to the firewall itself, not just forwarded ones. |
| `srcnat` | Source NAT (masquerade/SNAT) — evaluated in `postrouting`, after the routing decision. |

It deliberately does **not** hook `input` — traffic destined to the
firewall's own management IP (SSH, LuCI/UI, etc.) isn't this tool's concern.

---

## How Rule ID and NAT ID are determined

- **Rule ID**: nftables writes each rule's `comment` into the trace output,
  and on this build `fw4` populates that comment with the UCI rule's name
  (stripping the `!fw4: ` prefix it adds to auto-generated rules). If a
  packet's path goes through a `jump`/`goto` to another chain with no
  comment on that particular hop, `fwtrace` falls back to showing the
  target chain name, so you still know where it went.
- **NAT ID**: when the terminal hop is on a NAT chain (chain name contains
  `nat`) or the matched rule text mentions `masquerade`/`snat`/`dnat`,
  `fwtrace` queries `conntrack -L` for that exact flow and reports the real
  translated address:port — the same original/reply tuple `conntrack -L`
  itself shows, just extracted into a one-line summary.

---

## Deduplication

nftables assigns a **new trace id to every single packet**, so without
dedup an established connection would print one line per packet forever.
`fwtrace` keeps a flow key (`proto`/`saddr`/`sport`/`daddr`/`dport`) and only
prints again when:
- it's a flow it hasn't reported yet, or
- the verdict/chain for a previously-seen flow **changes** (e.g. it was
  passing and is now hitting a different rule and being dropped).

This was verified directly: feeding two packets of the identical flow
through the tracer produces exactly one output line, not two.

---

## Caveats

| Caveat | Detail |
|---|---|
| **Don't run two `fwtrace` sessions at once** | The probe-rule marker (`fwtrace-trace`) is a fixed string, not unique per run. A second session's cleanup (on exit, or via `--cleanup`) will remove the *first* session's still-in-use probe rules too, silently cutting off its output. This was observed directly during testing. |
| Ctrl‑C only works in the **foreground** | Same underlying shell rule as any interactive script: if you ever background it with `&` from another script, `SIGINT` won't reach it (POSIX shells auto-ignore `SIGINT`/`SIGQUIT` for commands started with `&`). Use `--cleanup` afterward, or send `SIGTERM` instead, in that case. Normal interactive terminal use is unaffected. |
| NAT ID only appears for **new** connections | NAT chains are only evaluated by the kernel for the first packet of a new connection — already-established connections skip NAT evaluation entirely (standard netfilter behavior). Trigger a fresh connection if you need to see the NAT line. |
| Unqualified `host`/`net`/`port` = destination only | Use `src ...` explicitly for the other direction. |
| No traffic to the firewall itself | By design (see [Hooked chains](#hooked-chains)) — not a bug. |
| Fully non-invasive | The probe is a non-terminating `meta nftrace set 1` statement — it never changes accept/drop/NAT behavior, only observes it. Verified live against active traffic without disruption. |

---

## Recovering from a killed session

If `fwtrace` is killed uncleanly (e.g. the SSH session drops mid-run) and
its probe rules are left behind:
```sh
fwtrace --cleanup
```
This scans all three hooked chains for anything tagged with the
`fwtrace-trace` marker and removes it, reporting how many rules were found.
