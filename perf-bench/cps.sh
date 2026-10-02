#!/bin/bash
# cps.sh <label>   (on the client): 3000 small HTTP requests, 60 in parallel, to a web server behind the firewall (python3 -m http.server 8099)
SERVER=${SERVER:-10.100.1.111}
s=$(date +%s.%N)
seq 3000 | xargs -P 60 -I{} curl -s -o /dev/null -m 10 "http://$SERVER:8099/f"
e=$(date +%s.%N)
echo "$1: $(echo "3000 / ($e - $s)" | bc -l | cut -c1-6) req/s"
