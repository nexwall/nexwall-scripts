# Queue watchdog: where its logs are, and how to enable and find core dumps

**Applies to:** Nexwall Firewall 26.0.0-rc1 and later  ·  Tool: [`nfq-watchdog`](../nfq-watchdog/nfq-watchdog.md)  ·  Background:
[`kba-dpi-engine-stall.md`](kba-dpi-engine-stall.md)

The watchdog has **no log file of its own**. It writes to four places, each for a different purpose.

## 1. Where everything is

| What | Where | Survives a reboot? | Use |
|---|---|---|---|
| **Log messages** (what happened, when, what it did) | the system log, tag `nexwall-nfq-watchdog`: **Log Viewer** (search `app_name:nexwall-nfq-watchdog`), and `/var/log/messages` | Log Viewer: **yes** (kept 30 days, stored on `/mnt/data/victoria-logs-data`). `/var/log/messages`: **no** (`/var` is `/tmp`, in RAM) | first place to look; shows stalls, the action taken, restarts |
| **Event history** (one line per stall) | `/root/nfq-stall/events.log` | yes | quick list, also drives the restart limit and the alert |
| **Diagnostic report** (one folder per stall) | `/root/nfq-stall/<YYYYMMDD-HHMMSS>/report.txt` | yes (newest 10 kept) | why it fired: queue table, memory, threads, sockets, kernel log |
| **Core dump** (only if enabled, section 3) | `/root/nfq-stall/<YYYYMMDD-HHMMSS>/netifyd.core.gz` | yes (newest 2 kept) | root-cause analysis by engineering |
| **Metric and alert** | metric `nexwall_nfq_watchdog` in the metrics database; alerts `DpiEngineStalled` and `DpiEngineRestartLimit` | yes | notification in the web interface |
| Cron entry (proof that it runs every minute) | `crond` lines in the system log, `* * * * * /usr/sbin/nexwall-nfq-watchdog` in `/etc/crontabs/root` | log: as above | check that it is alive |

### Reading the log messages

In the web interface: **Log Viewer** and search `nexwall-nfq-watchdog`. On the CLI:

```sh
grep nexwall-nfq-watchdog /var/log/messages | tail                # since the last reboot only
```

```sh
curl -s 'http://127.0.0.1:9428/select/logsql/query' --data-urlencode 'query=app_name:nexwall-nfq-watchdog' --data-urlencode 'limit=20'
```

Messages you can see:

| Message | Meaning |
|---|---|
| `queue(s) 50 51 52 53 stalled, owner: netifyd, action: restarted, report: /root/nfq-stall/…` | a stall was detected; `action` is one of `restarted`, `cooldown`, `limit`, `restart-disabled`, `dry-run` |
| `restarted netifyd` | the engine was restarted |
| `queue(s) … stalled again within …` | (older versions) restart skipped because one just happened |

If nothing is logged, nothing stalled: a healthy unit prints no watchdog message (only the cron line every minute).
The cron line is not a stall; ignore it.

### The event history

```sh
cat /root/nfq-stall/events.log
```

One line per stall, tab separated: time (epoch seconds), stalled queues, owner (`netifyd` or `snort`), action, report folder.
Convert the time with `date -d @<seconds>` on a PC, or `date -u -D %s -d <seconds>` on the firewall. Queues 50 to 57 belong to
the DPI engine (50-53 forwarded traffic, 54-57 traffic to and from the firewall), 4 to 7 to the intrusion prevention.

### The report

`/root/nfq-stall/<time>/report.txt` has these sections: `nfnetlink_queue` (queue, packets waiting, verdicts served),
`free`, `conntrack`, `top`, `loopback sockets`, `processes`, the per-thread state of the engine (thread id, state, CPU,
kernel wait point, the address of the lock it waits on), `nft netifyd` and `dmesg`. A line `core: …` at the end says what
happened with the core dump (saved, skipped, not produced).

## 2. Keep the evidence

Reports and cores are in `/root/nfq-stall/` on the flash (the overlay has limited space; check with `df -h /root`). Copy them
off the unit before a firmware upgrade or a factory reset: they are not part of the configuration backup.

```sh
scp -r root@<firewall>:/root/nfq-stall ./nfq-stall-<unit>
```

## 3. Core dumps

### What it is and why

The report says *that* the engine stalled. To see *why*, engineering needs the stack of every thread at that moment. A core
dump is a snapshot of the stalled process from which those stacks can be read.

### Enable (off by default)

```sh
uci set netifyd.watchdog.core='1'
uci commit netifyd
```

Nothing needs to be restarted: the watchdog reads the setting on every run (every minute). To turn it off again:

```sh
uci set netifyd.watchdog.core='0'
uci commit netifyd
```

Check the current settings: `uci show netifyd.watchdog`.

### What happens at a stall when it is on

1. The watchdog detects the stall and writes the report.
2. It raises the core-size limit of the running engine (the engine sets it to 0 when it starts) and sends it `SIGQUIT`.
   The engine blocks the normal abort signal in all its threads; `SIGQUIT` is the one left open on its main thread, and its
   default action is "stop and dump core".
3. For the moment of the dump the kernel core pattern is pointed at `/tmp` and then **restored** to what it was.
4. The core is compressed to `/root/nfq-stall/<time>/netifyd.core.gz` (permissions 600, typically 2 to 4 MB compressed, about
   17 MB raw), the temporary file in `/tmp` is deleted, and the engine is restarted as usual.

Safeguards: no core if less than 30 MB are free on `/root`; only the **newest 2** cores are kept; one core per stall; only for
the DPI engine (`netifyd`), not for `snort`. If the engine does not exit within 25 seconds of the signal, no core is produced
and the restart goes ahead; the report says so (`core: not produced …`).

While the core is being written the DPI engine is down for a few seconds (traffic keeps flowing, not inspected, as in any
restart).

### Where to find it

```sh
ls -lh /root/nfq-stall/*/netifyd.core.gz
```

Nothing else is left behind: if you see files named `/tmp/nfq-watchdog-core.*` the dump was interrupted; delete them.

### Privacy

A core dump contains the memory of the engine: IP addresses, host names and the first packets of recent connections. Treat it
like a packet capture: keep it private, send it only to Nexwall support, delete it when done (`rm /root/nfq-stall/*/netifyd.core.gz`).

### Reading it (engineering)

On the build/dev server, which has `gdb` and the builder's volumes (the build must be the one installed on the unit):

```sh
analyze-core /path/to/netifyd.core.gz
```

The output lists every thread with its stack, then the threads that are waiting on a lock. In a stall, look for several capture
threads (`ndCaptureNFQueue::Entry`) waiting on the same lock and the one thread that waits elsewhere while holding it. See
[`nfq-watchdog.md`](../nfq-watchdog/nfq-watchdog.md).

## 4. Quick answers

| Question | Answer |
|---|---|
| Is there a `.log` file? | No. Use the Log Viewer (tag `nexwall-nfq-watchdog`); `/var/log/messages` also has it until the next reboot. |
| How do I know the watchdog is running? | `crond` lines every minute in the log, `grep nexwall-nfq /etc/crontabs/root`, and `uci show netifyd.watchdog` (`enabled '1'`). |
| It restarted the engine, how do I see why? | the newest folder in `/root/nfq-stall/`, file `report.txt`; `events.log` for the history. |
| Where do I enable core dumps? | `uci set netifyd.watchdog.core='1' && uci commit netifyd`. |
| Where is the core? | `/root/nfq-stall/<time>/netifyd.core.gz` |
| How much space? | about 2 to 4 MB per core, at most 2 cores; reports a few tens of KB each, at most 10. |
| Does the restart limit apply to cores? | yes: a core is taken only when the watchdog is about to restart the engine (not in `cooldown`, `limit`, `restart-disabled` or `dry-run`). |
| The regression tests wrote messages to the log | `tests/test-watchdog.sh` uses stubs but the system logger is real, so it adds fake "stalled … restarted" lines. Ignore entries from the minutes when the tests ran. |
