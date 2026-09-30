#!/bin/sh
#
# Regression tests for nfq-watchdog. Run on a firewall (BusyBox ash) or any POSIX shell with awk:
#     sh tests/test-watchdog.sh [path to nfq-watchdog]
# Nothing real is touched: queue files, init scripts, the kill command and the core pattern are stubs, and
# NO_METRICS/NO_UCI keep it away from VictoriaMetrics and the real settings.
#
W="${1:-$(dirname "$0")/../nfq-watchdog}"
T=$(mktemp -d /tmp/wdtest.XXXXXX)
trap 'kill $SLEEPER 2>/dev/null; rm -rf "$T"' EXIT
pass=0; fail=0
ok()  { pass=$((pass + 1)); echo "ok   $1"; }
bad() { fail=$((fail + 1)); echo "FAIL $1"; }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got '$2', wanted '$3')"; fi; }

mkdir -p "$T/initd"
for s in netifyd snort; do printf '#!/bin/sh\necho "$(basename $0) $1" >> "%s/calls"\n' "$T" > "$T/initd/$s"; chmod +x "$T/initd/$s"; done
export SAMPLE_WAIT=1 NO_METRICS=1 NO_UCI=1 INITD="$T/initd" DUMP_ROOT="$T/dump"
run() { sh "$W" >/dev/null 2>&1; }
last_action() { tail -n 1 "$T/dump/events.log" 2>/dev/null | cut -f4; }
reset() { rm -rf "$T/dump" "$T/calls"; }

# 1 idle queue
reset; printf '   54 1 0 2 65531 0 0 1000 1\n' > "$T/q"; NFQ_FILE="$T/q" run
check "idle queue: no event" "$(ls "$T/dump" 2>/dev/null | wc -l | tr -d ' ')" "0"

# 2 frozen counter with waiting packets -> restart
reset; printf '   54 1 3 2 65531 0 0 1000 1\n' > "$T/q"; NFQ_FILE="$T/q" run
check "frozen counter: restarted" "$(last_action)" "restarted"
check "frozen counter: netifyd restarted" "$(cat "$T/calls" 2>/dev/null)" "netifyd restart"

# 3 big backlog that still moves -> restart
reset; ( i=0; while [ $i -lt 8 ]; do printf '   54 1 150 2 65531 0 0 %s 1\n' $((3000 + i)) > "$T/q"; i=$((i + 1)); sleep 1; done ) &
sleep 1; NFQ_FILE="$T/q" run; wait
check "big moving backlog: restarted" "$(last_action)" "restarted"

# 4 small backlog that moves -> nothing
reset; ( i=0; while [ $i -lt 8 ]; do printf '   54 1 5 2 65531 0 0 %s 1\n' $((4000 + i)) > "$T/q"; i=$((i + 1)); sleep 1; done ) &
sleep 1; NFQ_FILE="$T/q" run; wait
check "small moving backlog: no event" "$(ls "$T/dump" 2>/dev/null | wc -l | tr -d ' ')" "0"

# 5 snort queue restarts snort
reset; printf '    5 1 9 2 1518 0 0 1000 1\n' > "$T/q"; NFQ_FILE="$T/q" run
check "snort queue: snort restarted" "$(cat "$T/calls" 2>/dev/null)" "snort restart"

# 6 cooldown and hourly limit
printf '   54 1 3 2 65531 0 0 1000 1\n' > "$T/q"
reset; NFQ_FILE="$T/q" run; : > "$T/calls"; NFQ_FILE="$T/q" run
check "second stall at once: cooldown" "$(last_action)" "cooldown"
reset; mkdir -p "$T/dump"; N=$(date +%s)
for d in 3000 2000 1000; do printf '%s\t54\tnetifyd\trestarted\t-\n' $((N - d)) >> "$T/dump/events.log"; done
NFQ_FILE="$T/q" run
check "3 restarts this hour: limit" "$(last_action)" "limit"
check "limit: nothing restarted" "$(cat "$T/calls" 2>/dev/null | wc -l | tr -d ' ')" "0"
reset; DRY_RUN=1 NFQ_FILE="$T/q" run
check "dry run" "$(last_action)" "dry-run"

# 7 core capture: a stub kill that behaves like the kernel (ends the process and leaves the core file)
sleep 300 & SLEEPER=$!
cat > "$T/fakekill" <<EOF
#!/bin/sh
# usage: fakekill -QUIT <pid>
mode=\$(cat "$T/killmode" 2>/dev/null)
if [ "\$mode" = "ignore" ]; then exit 0; fi
pat=\$(cat "$T/pattern")
core=\$(echo "\$pat" | sed "s/%p/\$2/")
head -c 200000 /dev/zero > "\$core"
kill \$2
EOF
chmod +x "$T/fakekill"
echo "/original/pattern.%e" > "$T/pattern"
export KILL_CMD="$T/fakekill" CORE_PATTERN_FILE="$T/pattern" NO_PRLIMIT=1 CORE_WAIT=4
mkdir -p "$T/old1" "$T/old2" "$T/old3"
reset; mkdir -p "$T/dump/20200101-000001" "$T/dump/20200101-000002" "$T/dump/20200101-000003"
for n in 1 2 3; do echo x | gzip > "$T/dump/20200101-00000$n/netifyd.core.gz"; sleep 1; done
printf '   54 1 3 2 65531 0 0 1000 1\n' > "$T/q"
# CORE comes from settings: emulate with a tiny uci shim
mkdir -p "$T/bin"; printf '#!/bin/sh\ncase "$*" in *netifyd.watchdog.core*) echo 1;; *) exit 1;; esac\n' > "$T/bin/uci"; chmod +x "$T/bin/uci"
PATH="$T/bin:$PATH" NO_UCI= NETIFYD_PID=$SLEEPER NFQ_FILE="$T/q" sh "$W" >/dev/null 2>&1
d=$(ls -d "$T"/dump/2*/ | tail -n 1)
check "core: report says saved" "$(grep -c '^core: saved' "$d/report.txt")" "1"
check "core: compressed file in the report folder" "$(test -s "${d}netifyd.core.gz" && echo yes)" "yes"
check "core: file is private" "$(ls -l "${d}netifyd.core.gz" | cut -c1-10)" "-rw-------"
check "core: kernel pattern restored" "$(cat "$T/pattern")" "/original/pattern.%e"
check "core: only the newest 2 kept" "$(ls "$T"/dump/*/netifyd.core.gz | wc -l | tr -d ' ')" "2"
check "core: engine restarted afterwards" "$(cat "$T/calls")" "netifyd restart"
kill $SLEEPER 2>/dev/null

# 8 engine that does not exit on the signal: no core, restart still happens
sleep 300 & SLEEPER=$!
echo ignore > "$T/killmode"; reset
PATH="$T/bin:$PATH" NO_UCI= NETIFYD_PID=$SLEEPER NFQ_FILE="$T/q" sh "$W" >/dev/null 2>&1
d=$(ls -d "$T"/dump/2*/ | tail -n 1)
check "no core when the engine ignores the signal" "$(grep -c '^core: not produced' "$d/report.txt")" "1"
check "still restarted" "$(last_action)" "restarted"
kill $SLEEPER 2>/dev/null; rm -f "$T/killmode"

# 9 not enough space: skipped
sleep 300 & SLEEPER=$!
reset
CORE_MIN_FREE_KB=999999999 PATH="$T/bin:$PATH" NO_UCI= NETIFYD_PID=$SLEEPER NFQ_FILE="$T/q" sh "$W" >/dev/null 2>&1
d=$(ls -d "$T"/dump/2*/ | tail -n 1)
check "core skipped when space is short" "$(grep -c '^core: skipped' "$d/report.txt")" "1"
kill $SLEEPER 2>/dev/null

echo; echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
