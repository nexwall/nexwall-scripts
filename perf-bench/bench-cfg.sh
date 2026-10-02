#!/bin/sh
# bench-cfg.sh <dpi 0|1> <ips 0|1> <fastpath 0|1> <steering 0|1>   (on the firewall)
# Puts the firewall in a known state for a benchmark run and prints what it did. Starting netifyd takes about 30 s.
DPI=$1; IPS=$2; FP=$3; ST=$4
if [ "$DPI" = 1 ]; then pidof netifyd >/dev/null || { /etc/init.d/netifyd start >/dev/null 2>&1; sleep 30; }
else pidof netifyd >/dev/null && { /etc/init.d/netifyd stop >/dev/null 2>&1; for i in $(seq 1 20); do pidof netifyd >/dev/null || break; sleep 2; done; }; fi
if [ "$IPS" = 1 ]; then pidof snort3 >/dev/null || { /etc/init.d/snort start >/dev/null 2>&1; sleep 15; }
else pidof snort3 >/dev/null && { /etc/init.d/snort stop >/dev/null 2>&1; sleep 3; }; fi
uci set nexwall_perf.main.fastpath=$FP; uci commit nexwall_perf
uci set network.@globals[0].packet_steering=$ST; uci commit network; /etc/init.d/packet_steering reload >/dev/null 2>&1
nexwall-fastpath apply >/dev/null 2>&1
echo "dpi=$(pidof netifyd >/dev/null && echo 1 || echo 0) ips=$(pidof snort3 >/dev/null && echo 1 || echo 0) fastpath=$(nexwall-fastpath status | grep -o '"active": [a-z]*') rps=$(cat /sys/class/net/${IF:-eth2}/queues/rx-0/rps_cpus | tail -c 3)"
