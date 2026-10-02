# perf-bench

The helpers used for the performance validation on the lab (see `../docs/kba-dpi-ips-tuning.md` for the results).
Layout: a client VM on the LAN, a server VM behind a WAN port of the firewall (`iperf3 -s` and `python3 -m http.server 8099` with a 10 KB file `f`).

| Script | Where | What |
|---|---|---|
| `perf-sample.sh <s> <out>` | firewall | per-second Mbit/s, CPU, softirq, busiest CPU, biggest connection, queue drops, starting when a transfer starts (`IF=` picks the interface) |
| `bench-cfg.sh dpi ips fastpath steering` | firewall | puts DPI, IPS, fast path and packet steering in a known state |
| `bench.sh <label> [streams]` | client | 3 x 10 s iperf3 through the firewall, mean Mbit/s and retransmissions (`SERVER=` the far-side address) |
| `cps.sh <label>` | client | 3,000 small HTTP requests, 60 in parallel (connections per second) |

Method: change one setting at a time, repeat each line three times, alternate A/B runs, and compare Mbit/s and CPU % per Gbit/s.
On a shared hypervisor the absolute numbers move by 10 to 20 % between runs; only differences larger than that mean anything.
Check first that the path itself is not the limit: `ethtool -g <if>` (ring sizes), `/sys/class/net/<if>/queues/rx-0/rps_cpus`, `ksoftirqd` in `top`.
