# nexwall-fastpath

Hands connections the DPI and IPS engines are finished with to the kernel flow table (selective flow offload). Off by default.
`nexwall-fastpath apply | status | stop | list`. Full description, commands and troubleshooting:
[`../docs/kba-fast-path-offload.md`](../docs/kba-fast-path-offload.md); tuning context: [`../docs/kba-dpi-ips-tuning.md`](../docs/kba-dpi-ips-tuning.md).

Files: `nexwall-fastpath` (the tool, installed as `/usr/sbin/nexwall-fastpath`), `nexwall-fastpath.init` (service, `/etc/init.d/nexwall-fastpath`),
`99-nexwall-perf` (uci-defaults: creates `/etc/config/nexwall_perf`), `test_fastpath.py` (`python3 -m pytest nexwall-fastpath`).
