#!/bin/sh
# perf-sample.sh <seconds> <outfile>   (run on the firewall; IF=<wan interface>, default eth2)
# Waits (up to 15 minutes) until more than 3 Mbit/s arrive on the interface, then once a second records: Mbit/s received,
# total CPU busy %, softirq %, busiest CPU %, bytes of the biggest tracked connection, whether it is offloaded, queue drops.
N=${1:-60}; OUT=${2:-/tmp/perf.out}; IFACE=${IF:-eth2}
RX=/sys/class/net/$IFACE/statistics/rx_bytes
echo "t rx_mbps cpu_busy softirq max_cpu top_flow_bytes offload dropped" > $OUT
w=0; r1=$(cat $RX)
while [ $w -lt 900 ]; do sleep 1; w=$((w+1)); r2=$(cat $RX); [ $(( (r2-r1)*8/1000000 )) -gt 3 ] && break; r1=$r2; done
grep '^cpu' /proc/stat > /tmp/ps1; rx1=$(cat $RX); i=0
while [ $i -lt $N ]; do
  sleep 1; i=$((i+1))
  grep '^cpu' /proc/stat > /tmp/ps2; rx2=$(cat $RX)
  cpu=$(awk 'NR==FNR{for(k=1;k<=11;k++)a[FNR,k]=$k; next} {tot=0; for(k=2;k<=11;k++)tot+=$k-a[FNR,k]; idle=$5-a[FNR,5]+$6-a[FNR,6]; sirq=$8-a[FNR,8]; b=(tot-idle)*100/(tot?tot:1);
      if($1=="cpu"){B=b;S=sirq*100/(tot?tot:1)} else if(b>M)M=b} END{printf "%.0f %.0f %.0f", B,S,M}' /tmp/ps1 /tmp/ps2)
  top=$(awk '{line=$0; m=0; s=$0; while(match(s,/bytes=[0-9]+/)){v=substr(s,RSTART+6,RLENGTH-6)+0; if(v>m)m=v; s=substr(s,RSTART+RLENGTH)} if(m>best){best=m; off=(index(line,"[OFFLOAD]")?1:0)}} END{print best+0, off+0}' /proc/net/nf_conntrack)
  drops=$(awk '{d+=$6+$7} END{print d+0}' /proc/net/netfilter/nfnetlink_queue 2>/dev/null)
  echo "$i $(( (rx2-rx1)*8/1000000 )) $cpu $top $drops" >> $OUT
  cp /tmp/ps2 /tmp/ps1; rx1=$rx2
done
echo done >> $OUT
