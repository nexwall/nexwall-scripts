# `nfq-watchdog` - recovers the DPI / IPS engines when a packet queue stops being served

**Applies to:** Nexwall Firewall 26.0.0-rc1  ·  **Location:** `/usr/sbin/nexwall-nfq-watchdog` (cron, every minute)

## What it solves

The application inspection (DPI, `netifyd`) and the intrusion prevention (`snort`) read packets through kernel
**NFQUEUE** queues: `netifyd` queues 50-57 (forwarded traffic 50-53, traffic to and from the firewall 54-57), `snort`
queues 4-7. If a reader is alive but stops being served (or is far too slow) packets pile up in its queue and
everything hashed to that queue stalls. Typical symptoms: **new connections** to or through the firewall hang (SSH, web
interface, LAN clients) while already-open connections keep working, and Monitor > Live flows is empty.

The nftables `bypass` flag does not help (it only applies when no program is listening), and a crashed engine is not the
problem (that fails open). This is the "alive but not serving" case.

## How it decides

Every run takes three samples of `/proc/net/netfilter/nfnetlink_queue`, 10 seconds apart. A queue is **stalled** when
packets are waiting in all three samples and either

- its verdict counter did not move (nothing is being served), or
- at least `backlog` (default 64) packets are waiting in every sample (served far too slowly).

## What it does on a stall

1. Saves a **diagnostic report** in `/root/nfq-stall/<date-time>/report.txt` (queue table, memory, connection count, top,
   loopback socket queues of the flows daemons, per-thread state / kernel wait point / futex address of the engine,
   executable mappings, nft table, kernel log). The newest 10 reports are kept.
2. Appends a line to `/root/nfq-stall/events.log` (`time  queues  service  action  report`).
3. Logs at `daemon.crit` with tag `nexwall-nfq-watchdog` (visible in the Log Viewer).
4. **Restarts the owner** of the stalled queue (`netifyd` for 50-57, `snort` for 4-7), unless restricted by the settings.
5. Writes the `nexwall_nfq_watchdog` metric every run; the alert rules `DpiEngineStalled` (warning, for one hour after an
   event) and `DpiEngineRestartLimit` (critical) read it and show up in the web interface notifications.

Possible `action` values: `restarted`, `cooldown` (another restart less than 5 minutes ago), `limit` (restart budget of
the hour used up), `restart-disabled`, `dry-run`.

## Settings (`/etc/config/netifyd`)

```
config watchdog 'watchdog'
	option enabled '1'       # 0 = watchdog completely off
	option restart '1'       # 0 = detect, report and alert, never restart
	option max_restarts '3'  # most restarts per hour; beyond that it only reports and alerts
	option backlog '64'      # packets waiting in every sample that count as a stall
	option core '0'          # 1 = save a core dump of a stalled netifyd before restarting it (root-cause analysis)
```

```sh
uci set netifyd.watchdog.restart='0' && uci commit netifyd     # report only
uci set netifyd.watchdog.enabled='0' && uci commit netifyd     # off
```

The defaults are shipped with the firmware; no service restart is needed after changing them (read on every run).

## Core dump for root-cause analysis (`core '1'`)

A report says *that* the engine stalled; to see *why* (which thread holds the lock the others wait for) a stack trace of every
thread is needed. With `core` on, the watchdog, before restarting `netifyd`:

1. raises the core limit of the running engine (it sets it to 0 at start) and sends it `SIGQUIT`: the engine blocks the abort
   signal in all threads but leaves `SIGQUIT` (default action: terminate and dump core) unblocked in its main thread;
2. points the kernel core pattern at `/tmp` for the moment of the dump and restores it afterwards;
3. compresses the core to `/root/nfq-stall/<time>/netifyd.core.gz` (mode 600; typically 2 to 4 MB), skips it when less than
   30 MB are free, and keeps only the newest 2 cores.

A core holds traffic metadata (addresses, host names): treat it as private and share it only with support. It is **off by
default**; turn it on on a unit that stalls.

Read it on the build/dev server (needs `gdb` and the builder's volumes, for the build that produced the unit's firmware):

```sh
analyze-core /path/to/netifyd.core.gz          # stacks of every thread + the threads waiting on a lock
```

In a stall, look for several capture threads (`ndCaptureNFQueue::Entry`) waiting on the same lock and the one thread that is
waiting somewhere else while it holds it. Verified on a healthy engine (8 capture threads idle in `select`, 4 detection threads
waiting, the plugin threads named).

## Related protections (same package family)

- **Management traffic skips the queue.** Traffic addressed to or sent by the firewall on TCP 22, 443 and 9090 is never
  queued to the engine, so SSH and the web interface stay reachable during a stall. Only the firewall's own traffic is
  exempt: forwarded traffic (e.g. LAN users browsing on 443) is still inspected. Change with the list
  `netifyd.config.mgmt_ports` (`none` = inspect them too); applied by `ns-netifyd-configure`.
- **Bounded queues (fail-open).** `queue_maxlen = 256` per queue in `/etc/netifyd/interfaces.d/10-nfqueue.conf`: when a
  queue is full the kernel accepts new packets uninspected instead of making them wait.

## Usage / testing

```sh
nexwall-nfq-watchdog                 # one check (takes ~20 s), normally run by cron
cat /root/nfq-stall/events.log       # history
ls /root/nfq-stall/                  # reports
```

Test hooks (environment): `NFQ_FILE` (use a fake queue file), `DRY_RUN=1`, `SAMPLE_WAIT`, `BACKLOG`, `DUMP_ROOT`,
`NO_UCI=1`, `NO_METRICS=1`, `INITD` (directory with stub init scripts), `KILL_CMD`, `CORE_PATTERN_FILE`, `NO_PRLIMIT=1`,
`CORE_WAIT`, `NETIFYD_PID`, `CORE_MIN_FREE_KB`.

The regression tests (19 checks: idle, frozen, backlog, snort, cooldown, limit, dry run, core capture and its failure modes) run
on a firewall: `sh tests/test-watchdog.sh /usr/sbin/nexwall-nfq-watchdog`.

```sh
printf '   54 1 150 2 65531 0 0 1000 1\n' > /tmp/q     # queue 54: 150 packets waiting, counter frozen
NFQ_FILE=/tmp/q SAMPLE_WAIT=1 DRY_RUN=1 DUMP_ROOT=/tmp/wd nexwall-nfq-watchdog
cat /tmp/wd/events.log
```

## Caveats

- Worst-case detection time is about 80 seconds plus the time the engine needs to restart.
- A restart resets the engine's live flow table; rule enforcement on already-labelled connections continues.
- It does not fix the cause of a stall; it limits the damage and captures the evidence. See the KBA
  [`docs/kba-dpi-engine-stall.md`](../docs/kba-dpi-engine-stall.md).
