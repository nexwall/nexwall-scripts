# `drppkt` — Live Dropped/Matched-Packet Trace for Nexwall

**Applies to:** Nexwall Firewall 26.0.0-rc1 (nftables / `fw4` backend)
**Location:** `/usr/sbin/drppkt`

## What it does

`drppkt` shows, live and filtered, which firewall rule a packet actually
hit — including its Rule ID (the matched rule's name/comment) and, when the
packet went through a NAT chain, its NAT ID (the matched NAT rule's
name/comment). It's built entirely on nftables' own packet tracer
(`nft monitor trace`).

## Why this exists

Nexwall (nftables/`fw4`) has no single built-in command that shows this.
`nft monitor trace` gives it to you for free: turn on a per-packet trace
flag, and the kernel reports every chain and rule the packet passes
through, including each rule's `comment` — and on this build, `fw4` writes
the UCI rule's name into that comment automatically. So a traced packet
hitting your `Allow-HTTPS-from-WAN` rule literally shows
`Allow-HTTPS-from-WAN` in the output. That comment is the Rule ID. NAT
rules (masquerade, DNAT) get the same treatment in the `dstnat`/`srcnat`
chains — that's the NAT ID.

**Non-invasive by design:** the probe is a non-terminating
`meta nftrace set 1` statement — it never changes accept/drop/NAT behavior,
only observes it. Verified live against active traffic without disruption.

---

## Usage

```
Usage: drppkt [-i seconds] <filter...>

Filter tokens (join multiple with "and"):
  host <ip>              match as destination
  src host <ip>          match as source
  dst host <ip>          match as destination
  net <cidr>             match as destination network
  src net <cidr>         match as source network
  dst net <cidr>         match as destination network
  port <n>               match as destination port
  src port <n>           match as source port
  dst port <n>           match as destination port
  proto <tcp|udp|icmp>   restrict to a protocol

Options:
  -i SECS   auto-stop and clean up after SECS seconds (default: until Ctrl-C)
  -h        show this help

Examples:
  drppkt host 10.10.10.1 and port 21
  drppkt src host 10.10.10.1
  drppkt dst host 192.168.1.10 and dst port 443
  drppkt net 10.0.0.0/24 -i 30
```

An unqualified `host`/`net`/`port` matches as the **destination**. Use the
explicit `src ...` form for the other direction.

Hooks the `dstnat`, `input`, and `forward` chains, so it covers both
traffic destined to the firewall itself and traffic being routed/NAT'd
through it.

### Sample output

```
Filter:  ip daddr 192.168.1.242 th dport 443
Tracing via chains: dstnat input forward  (probe tag DRPPKT12345)
Ctrl-C to stop and remove the probe rules.

[a1b2c3d4] RULE input              !fw4: Handle inbound flows                    -> ACCEPT
```

Ctrl‑C to stop — this removes the probe rules, kills the background helper
processes, and deletes the temporary FIFO automatically.

---

## Worked example: confirming a LAN→WAN block rule

Say you've just added a rule blocking `lan → wan` forwarding, and want to
confirm it's actually that rule doing the blocking (not something else,
like a missing route or an upstream ISP issue):

```sh
drppkt src net 192.168.1.0/24 and dst port 443
```
(matching your LAN subnet destined anywhere on 443; adjust to your actual
LAN CIDR and the port/host you were testing with)

What you'll see for a **blocked** packet is a trace ending like:
```
[a1b2c3d4] RULE forward            !fw4: Handle lan IPv4/IPv6 forward traffic    -> JUMP
[a1b2c3d4] RULE forward_lan        <your-block-rule-name>                        -> DROP
```
That last line **is your confirmation**: the exact UCI rule name responsible
shows up as the Rule ID, with verdict `DROP`. If instead you see `ACCEPT`
from a different, earlier rule, that tells you traffic never reached your
new block rule at all — usually because an existing broader "lan to wan"
allow rule (often auto-created, e.g. `!fw4: Accept lan to wan forwarding`)
sits above it and already accepted the packet. **Rule order matters in
`fw4`/nftables** — a block rule added after a broader allow rule for the
same traffic never gets evaluated.

If the traffic was also expected to be NATted (masqueraded) outbound on the
WAN, and it's genuinely being blocked before reaching the `forward` chain
verdict, you generally will **not** see a `srcnat`/masquerade line at all
in the trace — confirming the packet never got far enough to need NAT,
which is exactly what you'd want to see for a working LAN→WAN block.

To check the reverse — that the block didn't accidentally affect something
it shouldn't have (e.g., existing established sessions) — re-run the same
`drppkt` command while an already-open browser session tries to load a page
from that subnet; you should see the same `DROP` line for new connection
attempts, but note existing **already-established** connections may
continue briefly, since conntrack's own state tracking, not the new rule,
governs those until they time out — the block rule only stops **new**
connections until the ruleset is fully reloaded/flushed.

---

## Caveats

| Caveat | Detail |
|---|---|
| Ctrl-C only works in the **foreground** | If you ever run `drppkt` backgrounded with `&` (e.g., from another script), `Ctrl-C`/`kill -INT` will **not** stop it — POSIX shells set `SIGINT`/`SIGQUIT` to be ignored for any command started with `&`, and that can't be re-trapped by the child. Use the `-i SECONDS` flag or `kill -TERM <pid>` instead in that case. Interactive terminal use (the normal case) is unaffected. |
| Unqualified `host`/`net`/`port` = destination only | Doesn't attempt "match either direction". Use `src host`/`src port` explicitly for the other direction. |
| NAT ID only appears for **new** connections | NAT chains (`dstnat`/`srcnat`) are only evaluated by the kernel for the first packet of a new connection — established connections skip NAT evaluation entirely (standard netfilter behavior), so you won't see a NAT ID line when testing against an already-open connection. Trigger a fresh connection to see it. |
| No reason code beyond the rule name | The Rule ID is the UCI rule's name (or `fw4`'s auto-generated description for built-in rules); there's no separate numeric "reason code". |
| Fully non-invasive | Verified live: probe rules only ever set the trace flag and fall through — they never change accept/drop/NAT behavior, and are removed automatically (rule, background process, and temp FIFO) on exit or timeout. |

## Recovering from a killed session

If `drppkt` is killed uncleanly and its probe rules are left behind, the
`-i` auto-timeout and the exit trap normally handle cleanup, but for a
manual sweep:
```sh
for c in dstnat input forward; do
  nft -a list chain inet fw4 $c | grep DRPPKT
done
```
then `nft delete rule inet fw4 <chain> handle <N>` for anything found.
