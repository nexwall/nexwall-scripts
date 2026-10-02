# KBA: Tuning Application Control (DPI) and Network Protection (IPS): the Settings tabs

**Product:** Nexwall Firewall  ·  **Component:** `netifyd` (DPI), `snort` (IPS), `nexwall-fastpath`  ·  **Audience:** administrators and support

Both engines read packets from kernel queues and share the CPU with forwarding. These are the controls that decide how much
CPU they use, what happens when they cannot keep up, and how the IPS reacts to a match. The defaults suit most firewalls.
Every UI setting is saved as a pending change: press **Apply changes** afterwards.

## Where each setting is

| Setting | UI location | UCI / command |
|---|---|---|
| DPI inspection threads | Application Control (DPI) > Settings > Performance | `dpi.engine.threads` (`auto`, `1`..`4`) |
| DPI overload behavior | Application Control (DPI) > Settings > Inspection engine overload | `dpi.engine.overload_action` (`allow`, `block`) |
| DPI queue limit | same card | `dpi.engine.queue_limit` (`128`, `256`, `512`, `1024`) |
| Fast path | DPI > Settings > Performance and IPS > Settings > Performance (same switch) | `nexwall_perf.main.fastpath` (`0`, `1`) |
| Spread network processing across CPU cores | same two cards (same switch) | `network.@globals[0].packet_steering` (`0`, `1`) |
| IPS on/off, protection level | Network Protection (IPS) > Settings | `snort.snort.enabled`, `snort.snort.ns_policy` (`connectivity`, `balanced`, `security`) |
| Behavior on a match | IPS > Settings | `snort.snort.action` (`default` = Block, `alert` = Detect only) |
| Also log detections that are not blocked | IPS > Settings | `snort.snort.ns_alert_excluded` (`0`, `1`) |
| IPS inspection depth | no UI (API/UCI) | `snort.nfq.max_inspect_bytes` (bytes, default `1048576`, `0` = unlimited) |
| Protected networks (HOME_NET) | IPS > Settings | `snort.snort.home_net` |
| Signatures | IPS > Settings > Signatures | `nexwall-ips-rules status \| update \| apply` |

## Application Control (DPI)

**Inspection threads.** How many capture instances (one thread each plus a detection thread) look at new connections.
*Automatic* uses half of the CPU cores, 1 to 4, and 1 for the firewall's own traffic (2 from 8 cores): a 2-core box gets 1,
a 4-core box 2, an 8-core box 4. DPI only needs the first 32 packets of a connection, so it needs far less CPU than the IPS.
More threads than cores only make the engines compete. Changing the value restarts Application Control for a few seconds
(the number of instances is created at start).

**When the engine is overloaded or stopped.** *Allow the traffic* (default, recommended): if the engine cannot keep up or is
not running, connections keep working but are not inspected, so application rules do not apply to them. *Block new
connections*: nothing passes without inspection; new connections fail until the engine is back (usually a minute or two);
existing connections keep working. The firewall's own traffic always fails open.

**Queue limit.** Packets that may wait per queue (128 to 1024). Larger absorbs bursts and adds latency; smaller drops
into the overload behavior sooner. Keep 256 unless you see drops.

## Network Protection (IPS)

**Protection level.** *Connectivity* blocks only high-confidence critical threats (fewest false positives, smallest rule
set, least CPU). *Balanced* adds high-confidence major threats. *Security* adds medium-confidence rules and scans/DoS
(most protection, more false positives, most CPU). Approximate blocking rules in the current bundle: 3,900 / 22,600 / 35,200.

**Behavior on a match.**
- *Block (recommended, default)*: traffic that matches a **blocking** rule of the chosen level is dropped and logged as `Drop`.
- *Detect only*: nothing is blocked, every match is only logged as `Alert`. Use it to see what the rules would do before
  blocking. A warning is shown while it is on; switch back to Block when done.

**Also log detections that are not blocked.** Adds detection-only rules (about 7,600, they never block) so Today's events also
shows suspicious traffic that is allowed (`Alert`). More events and a little more CPU. Leave off unless you want that visibility.
The Nexwall Labs alert test rule (header `X-Nexwall-IPS-Test: 1`) only appears with this on or in Detect only mode.

**Inspection depth (`snort.nfq.max_inspect_bytes`).** The IPS stops inspecting a connection after this many bytes (both
directions) and lets the rest pass. Lower = less CPU, but late payloads are not inspected; `0` = no limit (more CPU). It is
also the point after which the fast path can take over.

**Signatures.** Delivered by the Nexwall signature service (Snort Community, Emerging Threats Open and Nexwall Labs rules),
refreshed daily on the server and checked by the firewall every 30 minutes. A new bundle is validated with Snort before use;
if Snort rejects it, the previous rules stay. See *IPS > Settings > Signatures* ("Check for updates now").

## Shared: fast path and packet steering

**Fast path.** Forwards the rest of long transfers through the kernel flow table after the engines are done with them
(details, commands and troubleshooting: `kba-fast-path-offload.md`). Off by default; turn it on when long downloads,
backups or video load the CPU.

**Spread network processing across CPU cores (packet steering).** Lets all cores process network packets instead of mostly
one. It helps firewalls with several cores and network cards with a **single receive queue** (virtual NICs, many small
boards); multi-queue server NICs already spread the load. No effect on a single-core device. Check the effect with
`cat /sys/class/net/<wan>/queues/rx-0/rps_cpus` (a mask with more than one bit) and `top` (load on several cores).

## Starting points by hardware (not benchmarked yet)

| Hardware | DPI threads | IPS level | Fast path | Packet steering |
|---|---|---|---|---|
| 1-2 cores | Automatic (1) | Connectivity | On | On (2 cores) |
| 4 cores | Automatic (2) | Balanced | On if long transfers dominate | On if the NIC has one queue |
| 8+ cores | Automatic (4) | Balanced or Security | Optional | Usually not needed |

These are starting points, not measured results: a benchmark on the target hardware (Mbit/s per CPU %, with the IPS on) is
still to be done. Change one setting at a time and compare.

## How to check the effect

```sh
dpidbg status                                    # DPI queues: waiting packets and verdict counters
cat /proc/net/netfilter/nfnetlink_queue          # queues 50-5x DPI, 4-7 IPS: column 6 = dropped when the queue was full
top -b -n1 | head -15                            # who uses the CPU
nexwall-fastpath status                          # fast path state and accelerated connection count
nexwall-ips-rules status                         # signature bundle, policy, last check
ls /var/log/snort                                # IPS alerts (JSON)
```

Queue columns: `queue_total` (waiting now) should stay near 0; a growing `queue_dropped` means the engine cannot keep up:
lower the IPS level, enable the fast path, or give the engines more cores.

## Back to defaults

```sh
uci -q delete dpi.engine.threads
uci set dpi.engine.overload_action=allow; uci set dpi.engine.queue_limit=256
uci set nexwall_perf.main.fastpath=0
uci set network.@globals[0].packet_steering=0
uci set snort.snort.action=default; uci set snort.snort.ns_alert_excluded=0
uci set snort.nfq.max_inspect_bytes=1048576
uci commit; reload_config
```

## What to collect before contacting support

`uci show dpi.engine; uci show nexwall_perf; uci show snort | grep -v oinkcode`, `nexwall-fastpath status`,
`nexwall-ips-rules status`, `dpidbg status`, `cat /proc/net/netfilter/nfnetlink_queue`, the number of CPU cores
(`grep -c ^processor /proc/cpuinfo`), and the time and symptom (slow, dropped, blocked wrongly).
