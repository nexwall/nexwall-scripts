# KBA: Threat Shield: where the block lists come from, and how to check and troubleshoot them

**Product:** Nexwall Firewall  ·  **Component:** `nexwall-threat-feeds`, adblock (DNS filtering), banIP (IP blocking), license service  ·
**Audience:** administrators and support

## What it is

Threat Shield blocks two kinds of things with lists that Nexwall builds every day on its own server from vetted open sources:

- **Domains** (DNS filtering): the firewall's own DNS server (dnsmasq, through adblock) answers "not found" for a listed domain and for all
  its subdomains. Categories: malware, phishing, ransomware, scams and fraud, crypto mining, DoH/VPN/Tor/proxy bypass, adult, gambling,
  piracy, drugs, advertising and tracking, and a larger extended malware set.
- **IP addresses** (IP blocking): banIP drops traffic to and from listed addresses. Categories: botnet command and control, known attackers.

There is no cloud DNS service involved: the lists are files on the firewall and DNS stays local. The lists are delivered through the licence
service (trial or subscription), signed, and checked on the firewall before use. Without a licence no Nexwall lists are provided.

## How it works

1. Every 30 minutes (random delay) `nexwall-threat-feeds sync` asks the licence server for the signed catalog of the current bundle.
2. It verifies the signature, then downloads **only the categories that are switched on**, checking the size and SHA-256 of every file (compressed and plain).
3. adblock and banIP read the lists as local files (`file:///mnt/data/threat-feeds/<version>/dns-<category>.txt`). They are reloaded only when
   something changed, not on a timer.
4. If the licence service is not answering, the lists on the firewall stay. If the licence ends, the lists are taken away once.

First start: the categories marked as default (malware, phishing, ransomware, scams, botnet C2, known attackers) are switched on, but only where
nothing was chosen yet. Choices made with earlier versions are carried over (adult, gambling, piracy, DoH/VPN bypass, malware, privacy lists).

## Commands

| Command | What it does |
|---|---|
| `nexwall-threat-feeds status` | licence state, bundle version, last check, every category with entries, on/off and whether its file is on the firewall |
| `nexwall-threat-feeds status --json` | the same for scripts; includes the estimated DNS memory of the switched-on lists (`dns_memory_mib`) |
| `nexwall-threat-feeds update [--force]` | check the server and download what is switched on (does not touch adblock or banIP) |
| `nexwall-threat-feeds sync` | update, then reload adblock and banIP if something changed (what cron runs) |
| `nexwall-threat-feeds feeds-dns` / `feeds-ip` | the feed definitions handed to adblock / banIP (called by `ts-dns` / `ts-ip`) |
| `/etc/init.d/adblock status` | blocked domains, active feeds, dnsmasq memory |
| `/etc/init.d/banip status` | elements in the IP sets, active feeds |

Files: `/mnt/data/threat-feeds/` (catalog `manifest.json`, `state.json`, one folder per version, the two newest are kept),
`/etc/adblock/adblock.custom.feeds`, `/etc/banip/banip.custom.feeds`. Log: `grep nexwall-threat-feeds /var/log/messages`.

## Memory and speed

DNS lists cost about **75 bytes per domain** in dnsmasq (measured: 1.8 million domains = 134 MB). Plan before switching on large categories:

| Category | Entries (2026-10) | About |
|---|---|---|
| Malware (core) | 195,000 | 15 MB |
| Phishing | 486,000 | 36 MB |
| Scams and fraud | 186,000 | 14 MB |
| Ransomware, crypto mining, drugs, bypass, piracy | 2,000 to 54,000 each | 0.2 to 4 MB |
| Gambling | 226,000 | 17 MB |
| Advertising and tracking | 408,000 | 31 MB |
| Adult | 953,000 | 71 MB |
| Malware (extended, includes the core one) | 735,000 | 55 MB |

The default set is about 870,000 domains (65 MB). Firewalls with 2 GiB should stay near it; 4 GiB or more can take adult, advertising and the extended malware list.
Reloading dnsmasq with a large list interrupts DNS for a few seconds (about 10 seconds with 1.8 million domains); that is why reloads happen only when the lists change (usually once a day).

## Geo-blocking and the memory warning

Country blocks (banIP `country` feed) come from the same signed bundle: `nexwall-threat-feeds status` lists `country_v4` and `country_v6`, and the files are under `/mnt/data/threat-feeds/<bundle>/geo/`. The data is registry allocation data, so a few addresses may sit in another country than their users. Without a license banIP keeps its own download.
In the DNS blocklist page, a warning appears when the switched-on lists need more than a fifth of the installed memory, and an error above a third; switch off large categories or add memory.

## Troubleshooting

**No lists / "not licensed".** `nexwall-threat-feeds status` shows `license: unlicensed` or `last check: not licensed`. Register the firewall or ask for a trial; check `licensectl state`.

**"update failed".** `status` shows the reason. Typical: the firewall cannot reach the licence server (check `licensectl state`), or a file did not match its signed hash (retry
with `--force`; if it repeats, send the message to support). A failed update never removes the lists already on the firewall.

**Category switched on but not blocking.** `status` must show `(file ok)` for it; if not, run `nexwall-threat-feeds sync`. Then `/etc/init.d/adblock status` must list it under active feeds.
Test: `nslookup <listed domain> 127.0.0.1` answers NXDOMAIN. A client that uses its own DNS (DoH, a fixed 8.8.8.8) bypasses the filter unless DNS enforcement is on
(Threat Shield > DNS filtering > Settings: ports 53 and 853 are redirected to the firewall).

**A site is blocked that must work.** Add the domain to the DNS allowlist (Threat Shield > DNS filtering > Allowlist). Report it to support with the category: false positives are fixed in the
daily build (the build has its own allowlist of critical domains).

**banIP shows "processing" for minutes.** banIP downloads the feeds one by one. The Nexwall IP lists are local and take seconds; the slow part is geo-blocking
(`country` feed, one download per country, from a third party) and any feed of banIP's own list that is switched on. Check `grep banIP /var/log/messages`.

**DNS stops answering for a moment after a change.** dnsmasq restarts to load the lists (see Memory and speed). If it lasts minutes the lists are too large for the memory: switch off the biggest categories.

## What to collect before contacting support

`nexwall-threat-feeds status --json`, `/etc/init.d/adblock status`, `/etc/init.d/banip status`, `uci show adblock.global`, `uci show banip.global | grep -v oinkcode`,
`grep -E "nexwall-threat-feeds|adblock|banIP" /var/log/messages | tail -50`, `free -m`, and the name of the domain or address that is wrongly blocked or not blocked.
