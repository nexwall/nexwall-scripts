# `dpidbg` - look inside the DPI engine

**Applies to:** Nexwall Firewall 26.0.0-rc1  ·  **Location:** `/usr/sbin/dpidbg`

Support tool for questions like *why is this traffic "Unknown"?*, *is the engine healthy?*, *what catalog did it load?*
It uses the engine's own interfaces (control socket, flow table, debug mode); it never changes configuration.

## Commands

```sh
dpidbg status                          # engine state, packet queues, watchdog history
dpidbg unknown [-n 20]                 # what is unclassified right now, grouped by host
dpidbg catalog                         # rules loaded (applications, domains, networks) and their files
dpidbg capture [-s 30] [-i <ip>] [-o <file>]   # debug capture with summary
```

### `status`
Asks the engine on `/var/run/netifyd/netifyd.sock` (`{"command":"status"}`): version, uptime, flows, memory, CPU; then
the kernel queue table (queue, packets waiting, verdicts served) and the last watchdog events. A queue with many packets
waiting and a verdict counter that does not move is the signature of a stall (see the watchdog).

### `unknown`
Reads the live flow table (same source as Monitor > Live flows) and reports the share of flows and bytes whose
application is unknown, and the top hosts behind them (TLS server name, DNS name, or the remote IP). It also says how
many unknown flows have **no name at all**: those can only be classified by network, not by domain.

### `catalog`
Counts the rules in `netify-apps.conf` by type (`app`, `dom`, `net`, `nsd`), lists the catalog files and their dates.

### `capture`
Stops the service, runs the engine in debug mode (`netifyd -d -v -R`) for the given seconds (5-300), restores the service
(also on Ctrl-C) and prints a summary:

- the catalog line the engine printed at load time and any load errors;
- the number of detections with an application vs protocol only;
- the most frequent detections;
- **protocol-only flows by host**: the hosts to add to the catalog.

`-i <ip>` restricts the summary to one client. The raw log (real-time detections, including the matched category and the
host name per flow) stays in the output file (default `/tmp/dpidbg-<time>.log`).

**Impact:** inspection is paused while it runs (traffic keeps flowing, the queues fail open), the live flow table restarts
and already-labelled connections stay labelled. Use it in a maintenance window or on a test unit.

## Reading the raw capture

```
wan: e4pc------------- UDP [OL] 192.168.0.1:53 <-- [L] 192.168.0.136:43354
    : DNS.netify.microsoft          <- protocol.application (no ".netify.x" = application unknown)
    : H: teams.microsoft.com        <- host name the engine saw
    : CAT/APP: business CAT/PROTO: networking ...
```

An application is assigned by **domain** (`dom:` rules), **network** (`net:`), **protocol hints** or **soft-dissectors**
(`nsd:`) in the catalog. `DNS` plus a host without `.netify.<app>` means no rule covers that host.

## Requirements
`socat`, `python3`, `curl` (for the catalog log line), `netifyd`, the flows daemon (`ns.flows`).
