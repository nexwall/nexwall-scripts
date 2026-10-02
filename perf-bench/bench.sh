#!/bin/bash
# bench.sh <label> [streams]   (on the client behind the firewall; server: iperf3 -s on the far side)
# 3 runs of 10 s, 4 TCP streams by default, reverse direction (the server sends): Mbit/s and retransmissions per run, then the mean.
SERVER=${SERVER:-10.100.1.111}; P=${2:-4}; r=()
for i in 1 2 3; do
  v=$(iperf3 -c "$SERVER" -t 10 -P "$P" -R -J 2>/dev/null | python3 -c "import json,sys;d=json.load(sys.stdin);e=d['end'];print(round(e['sum_received']['bits_per_second']/1e6), e['sum_sent'].get('retransmits',0))")
  r+=("$v")
done
echo "$1 P=$P: ${r[*]}" | tr '\n' ' '; echo "${r[@]}" | awk '{s=0;for(i=1;i<=NF;i+=2)s+=$i;printf "=> mean %d Mbit/s\n", s/3}'
