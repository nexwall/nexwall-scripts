# KBA: New connections hang while the firewall looks healthy (DPI / IPS packet queue stall)

**Product:** Nexwall Firewall 26.0.0-rc1 and later  ·  **Component:** application inspection (DPI, `netifyd`), intrusion
prevention (`snort`)  ·  **Severity:** high (new connections delayed or failing for minutes)

## Symptoms

- SSH or the web interface do not answer from the WAN or LAN, while an **already open** session keeps working (for
  example the web interface is reachable on another port with an old connection).
- Users on the LAN cannot open new connections (new web pages, calls) while existing downloads continue.
- Monitor > Live flows is **empty** or frozen.
- CPU and memory look normal (idle above 95 %).
- A notification "The traffic inspection engine stopped responding and was recovered" appears, or the log contains
  `nexwall-nfq-watchdog` entries.

## Cause

The inspection engines read packets from kernel queues (NFQUEUE). If a reader stops being served, or is far too slow,
the packets wait in the queue and every connection whose first packets hash to that queue stalls. Connections that
already passed their first 32 packets are not affected. The firewall rule `queue flags bypass` does not apply because the
program is still running. (A crashed engine is different: it fails open and traffic flows.)

## Check (2 minutes)

```sh
dpidbg status
```
Look at the queue table: a queue with many packets **waiting** and a **verdicts** counter that does not increase between
two runs is stalled (queues 50-57 = DPI, 4-7 = IPS).

```sh
ls -lt /root/nfq-stall/ | head            # diagnostic reports, newest first
cat /root/nfq-stall/events.log            # history: time, queues, service, action
```

## Resolution

Automatic: the watchdog (`nexwall-nfq-watchdog`, every minute) restarts the owner of the stalled queue, at most
`max_restarts` times per hour. Expect recovery within about 2 minutes.

Manual, if the watchdog is off or its limit was reached:

```sh
/etc/init.d/netifyd restart        # DPI queues 50-57
/etc/init.d/snort restart          # IPS queues 4-7
```

If you cannot log in at all: use the console. Management ports (22, 443, 9090) to the firewall itself are excluded from
the DPI queue, so they stay reachable even when DPI stalls; if they still do not answer, suspect the IPS queues or
the system, not DPI.

## What to collect before contacting support

1. The newest report folders in `/root/nfq-stall/` (`report.txt`), `events.log`, and `netifyd.core.gz` if `watchdog.core` was on
   (it contains traffic metadata: send it only to support).
2. `dpidbg status` output and `dpidbg unknown` if the complaint is about traffic classification.
3. Whether a `netifyd` reload happened shortly before (DPI data/licence update, rule change): `grep netifyd` in the log
   viewer around the event time.
4. Time the problem started and stopped, which ports or clients were affected.

## Settings and prevention

| Setting (`/etc/config/netifyd`) | Default | Effect |
|---|---|---|
| `watchdog.enabled` | `1` | `0` turns the watchdog off |
| `watchdog.restart` | `1` | `0` = detect, report and alert, never restart |
| `watchdog.max_restarts` | `3` | restarts per hour before it only reports and alerts |
| `watchdog.backlog` | `64` | packets waiting in every sample that count as a stall |
| `watchdog.core` | `0` | `1` saves a core dump of the stalled engine (for support) |
| `config.mgmt_ports` | `22 443 9090` | TCP ports of the firewall's own management traffic that skip DPI |
| `dpi.engine.queue_limit` | `256` | packets that may wait per queue (128, 256, 512 or 1024); written to `10-nfqueue.conf: queue_maxlen` |
| `dpi.engine.overload_action` | `allow` | what happens to **new connections through the firewall** when a queue is full or the engine is not running: `allow` = they pass uninspected (application rules do not apply to them), `block` = they are dropped until the engine is back |

Tools: [`nfq-watchdog`](../nfq-watchdog/nfq-watchdog.md), [`dpidbg`](../dpidbg/dpidbg.md).

## Overload decision: allow or block

Application Control (DPI) > Settings > **Inspection engine overload**, or `/etc/config/dpi` section `engine`:

```
config engine 'engine'
	option overload_action 'allow'   # or 'block'
	option queue_limit '256'         # 128, 256, 512 or 1024
```

- **allow (default, recommended):** when the engine cannot keep up (its queue is full) or is not running, new connections pass
  without inspection. Nothing breaks for users, but application blocking rules do not apply to those connections meanwhile.
- **block:** nothing passes without inspection, so rules cannot be bypassed, but new connections through the firewall fail
  until the engine is back (an automatic restart takes one to two minutes). Existing connections keep working.
- Only **forwarded** traffic follows `block`. The firewall's own traffic (DNS, updates, licensing) and access to the web
  interface and SSH are never blocked.
- A *stuck* engine (alive but not serving) is covered by the watchdog in both modes: packets wait until the queue limit is
  reached, then the action applies; the watchdog restarts the engine.
- Changing the setting needs **Apply changes**; the firewall rule and the engine's queues are updated without restarting it.

## Notes

- The stall itself is under investigation; the reports the watchdog saves are what the engineering team needs.
- Restarting the DPI engine resets the live flow table; blocking rules keep applying to connections already labelled.
