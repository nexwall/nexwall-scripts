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
| Larger network card buffers | same two cards (same switch) | `nexwall_perf.main.ring_buffers` (`0`, `1`) |
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
(details, commands and troubleshooting: `kba-fast-path-offload.md`). On by default on new installations (it only touches connections the engines are finished with); turn it off if you need
every packet of long connections to be inspected or a rule change to reach existing connections at once.

**Spread network processing across CPU cores (packet steering).** Lets all cores process network packets instead of mostly
one. It helps firewalls with several cores and network cards with a **single receive queue** (virtual NICs, many small
boards); multi-queue server NICs already spread the load. No effect on a single-core device. Check the effect with
`cat /sys/class/net/<wan>/queues/rx-0/rps_cpus` (a mask with more than one bit) and `top` (load on several cores).

**Larger network card buffers (`ring_buffers`).** Raises the receive and transmit rings of the physical interfaces to the
hardware maximum (`ethtool -G <if> rx max tx max`, applied at boot, on interface changes and when the setting changes).
Virtual network cards (e1000 on VMware, VirtualBox and similar) start with 256 descriptors and drop packets in bursts: slow
TCP with thousands of retransmissions, UDP loss. Check with `ethtool -g <if>` (current vs maximum). Safe on physical
hardware. On by default for new installations.

## Measured on the lab (virtual firewall, 4 vCPU, e1000, 2026-10-02)

Client VM through the firewall to a server VM, iperf3, 4 TCP streams, reverse direction, 3 x 10 s per line (Mbit/s, mean):

| Configuration | Result |
|---|---|
| Direct between the two VMs (no firewall) | about 2,700 |
| Firewall, no DPI/IPS, default NIC rings, no steering | 17 to 120, thousands of retransmissions |
| same, rings at maximum | 100, one retransmission |
| rings at maximum + packet steering | 694 |
| + DPI and IPS on (balanced) | 736 |
| + fast path | 740 to 890 (two A/B pairs: fast path 866 and 920 Mbit/s at 60 and 52 CPU % per Gbit/s, off 840 and 758 at 60 and 65) |

Reading: on this virtual NIC the first limit was the ring size (UDP at 300 Mbit/s lost 53% with 256 descriptors, 0.3% with 4096),
the second the single interrupt that kept one core at 100% (steering moved the load: 100 to about 700 Mbit/s). With those two
fixed, DPI and IPS cost little for large transfers, because they only inspect the first 32 packets / 1 MiB of each connection,
and the fast path gave about 10% more throughput for about 10% less CPU per Gbit/s (inside the noise of a shared host).
Many small connections (3,000 short HTTP requests, 60 in parallel): about 155 requests/s with DPI and IPS on against 163 to 184 without
(the test server was the limit). Absolute numbers depend on the hypervisor; use them for comparing settings, not as product specs.

## Starting points by hardware (not benchmarked yet)

| Hardware | DPI threads | IPS level | Fast path | Packet steering | Larger buffers |
|---|---|---|---|---|---|
| 1-2 cores | Automatic (1) | Connectivity | On | On (2 cores) | On |
| 4 cores | Automatic (2) | Balanced | Optional (about +10% on long transfers in the lab) | On (a single-queue or virtual NIC loses most of its speed without it) | On |
| 8+ cores | Automatic (4) | Balanced or Security | On | Usually not needed on multi-queue NICs | On for virtual NICs |

The lab numbers above are from a virtual firewall; a benchmark on the target hardware is still to be done. Change one setting at a time and compare.

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
uci set nexwall_perf.main.ring_buffers=0
uci set snort.snort.action=default; uci set snort.snort.ns_alert_excluded=0
uci set snort.nfq.max_inspect_bytes=1048576
uci commit; reload_config
```

## What to collect before contacting support

`uci show dpi.engine; uci show nexwall_perf; uci show snort | grep -v oinkcode`, `nexwall-fastpath status`,
`nexwall-ips-rules status`, `dpidbg status`, `cat /proc/net/netfilter/nfnetlink_queue`, the number of CPU cores
(`grep -c ^processor /proc/cpuinfo`), and the time and symptom (slow, dropped, blocked wrongly).

## Defaults on a new installation

| Setting | Default | Why |
|---|---|---|
| DPI inspection threads | Automatic | half of the cores, leaves the rest to the IPS and forwarding |
| IPS protection level | Balanced | measured at full speed with the engines on; Connectivity only if the box is very small |
| IPS behavior | Block | |
| Fast path | On | after inspection only; about +10% throughput and -10% CPU in the lab |
| Packet steering | On when there is more than one core | single-queue or virtual NICs went from 100 to about 700 Mbit/s |
| Larger network card buffers | On | virtual NICs drop bursts with the small default buffers |

Existing units keep what they have; the defaults are created only when the `nexwall_perf` settings do not exist yet.

## Connection table and memory

Every tracked connection costs about 5.6 KB (kernel, DPI and IPS together, measured with 77,000 connections), so the
connection limit is derived from the installed memory: 32 entries per MiB, at least 65,536 (2 GiB: 65,536, 4 GiB: 131,072,
8 GiB: 253,952, 16 GiB: 524,288). `nexwall-fastpath apply` sets it at boot and on reload (`nexwall_perf.main.conntrack_auto=0`
keeps a manual `net.netfilter.nf_conntrack_max`). The kernel's own default (about 1,000,000 entries on 8 GiB) would let the
engines use more memory than a small firewall has: the lab firewall stopped answering when the table grew far beyond what
its 2 GiB could hold. Watch **Tracked connections** in the Engine monitor; if it stays near 100 % the limit is too low for
the number of users and more memory is the answer, not a bigger table.

IPS queues and threads follow the number of CPU cores (up to 16) automatically (`snort.nfq.cpu_auto=0` keeps a manual value);
each extra thread adds about 15 MB of memory.

## Engine monitor

The Settings tab of Application Control (DPI) and Network Protection (IPS) starts with a live **Engine monitor** (refresh every
5 seconds): CPU of the engine (percent of the whole system and of one core) and of the whole system, memory of the engine and of
the system, **dropped packets** (packets the engine did not inspect because its queue was full or it did not answer; they
are let through, fail open) as a ten-minute total, the worst percentage of traffic and a per-minute chart, packets waiting in
the queues, and the tracked connections against the limit. A steady zero in dropped packets is the goal. Values come from
`ubus call ns.dpi get-engine-metrics` (same for `ns.snort`).
