import importlib.machinery
import importlib.util
import os

import pytest

SCRIPT = os.path.join(os.path.dirname(__file__), 'nexwall-fastpath')


@pytest.fixture()
def mod():
    loader = importlib.machinery.SourceFileLoader('nexwall_fastpath', SCRIPT)
    spec = importlib.util.spec_from_loader('nexwall_fastpath', loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    return m


def make_sys_net(tmp_path, layout):
    """layout: device -> list of (kind, name) with kind brif or lower"""
    for device, below in layout.items():
        (tmp_path / device).mkdir(exist_ok=True)
        for kind, name in below:
            if kind == 'brif':
                (tmp_path / device / 'brif').mkdir(exist_ok=True)
                (tmp_path / device / 'brif' / name).mkdir()
            else:
                (tmp_path / device / f'lower_{name}').mkdir()
            (tmp_path / name).mkdir(exist_ok=True)
    return str(tmp_path)


def test_bridge_ports_and_vlans_are_resolved(mod, tmp_path):
    sys_net = make_sys_net(tmp_path, {
        'br-lan': [('brif', 'eth0'), ('brif', 'eth2.10')],
        'eth2.10': [('lower', 'eth2')],
        'eth1': [],
    })
    assert mod.lower_devices('br-lan', sys_net) == ['eth0', 'eth2']
    assert mod.lower_devices('eth1', sys_net) == ['eth1']
    assert mod.lower_devices('missing', sys_net) == []


def test_flow_devices_skip_tunnels_down_and_unset(mod, tmp_path):
    sys_net = make_sys_net(tmp_path, {'br-lan': [('brif', 'eth0')], 'eth1': [], 'tunrw1': [], 'wg0': []})
    interfaces = [
        {'interface': 'lan', 'up': True, 'proto': 'static', 'device': 'br-lan', 'l3_device': 'br-lan'},
        {'interface': 'wan', 'up': True, 'proto': 'dhcp', 'device': 'eth1', 'l3_device': 'eth1'},
        {'interface': 'vpn', 'up': True, 'proto': 'none', 'device': 'tunrw1'},
        {'interface': 'wg', 'up': True, 'proto': 'wireguard', 'device': 'wg0'},
        {'interface': 'wan2', 'up': False, 'proto': 'dhcp', 'device': 'eth3'},
        {'interface': 'loopback', 'up': True, 'proto': 'static', 'device': 'lo'},
    ]
    assert mod.flow_devices(interfaces, sys_net) == ['eth0', 'eth1']


def test_pppoe_uses_the_device_under_the_session(mod, tmp_path):
    sys_net = make_sys_net(tmp_path, {'eth1': [], 'pppoe-wan': []})
    interfaces = [{'interface': 'wan', 'up': True, 'proto': 'pppoe', 'device': 'eth1', 'l3_device': 'pppoe-wan'}]
    assert mod.flow_devices(interfaces, sys_net) == ['eth1']


@pytest.mark.parametrize('ips,setting,depth,expected', [
    (False, 'auto', '1048576', 262144),
    (True, 'auto', '1048576', 1048576),
    (True, 'auto', '4194304', 4194304),
    (True, 'auto', '1000', 262144),      # never below the floor
    (False, '2000000', '1048576', 2000000),
    (True, '100', '1048576', 262144),
    (True, 'junk', '1048576', 1048576),
    (True, None, '1048576', 1048576),
])
def test_threshold(mod, monkeypatch, ips, setting, depth, expected):
    monkeypatch.setattr(mod, 'uci_get', lambda c, s, o, d=None: depth)
    assert mod.min_bytes(ips, setting) == expected


def test_ruleset_with_the_traffic_engine(mod):
    text = mod.render(['eth0', 'eth1'], 1048576, True)
    assert 'devices = { eth0, eth1 };' in text
    assert '        counter\n' in text   # connection tracker counters stay current while offloaded
    assert 'filter + 20' in text            # behind both engines' hooks
    assert 'ct state != established return' in text
    assert 'ct label "netify-analyzed" jump candidate' in text
    for label in ('netify-blocked', 'bulk', 'best_effort', 'video', 'voice'):
        assert f'ct label "{label}" return' in text
    assert 'ct packets > 32 ct bytes > 1048576 flow add @ft' in text
    # the label rules come before the offload rule
    assert text.index('ct label "voice" return') < text.index('flow add @ft')


def test_ruleset_without_the_traffic_engine_has_no_labels(mod):
    text = mod.render(['eth1'], 262144, False)
    assert 'ct label' not in text
    assert 'jump candidate' in text
    assert 'ct bytes > 262144 flow add @ft' in text


def test_offloaded_flows_are_counted(mod, tmp_path):
    f = tmp_path / 'ct'
    f.write_text('ipv4 2 tcp 6 100 ESTABLISHED src=1 [OFFLOAD] mark=0\nipv4 2 tcp 6 100 ESTABLISHED src=2 mark=0\n')
    assert mod.offloaded_flows(str(f)) == 1
    assert mod.offloaded_flows(str(tmp_path / 'none')) == 0


def test_flow_listing(mod, tmp_path):
    f = tmp_path / 'ct'
    f.write_text('ipv4 2 tcp 6 100 ESTABLISHED src=10.0.0.2 dst=1.1.1.1 sport=40000 dport=443 packets=5 bytes=1000 '
                 'src=1.1.1.1 dst=192.168.0.2 sport=443 dport=40000 packets=9 bytes=9000 [OFFLOAD] mark=0\n'
                 'ipv4 2 udp 17 30 src=10.0.0.3 dst=8.8.8.8 sport=1 dport=53 packets=1 bytes=60 src=8.8.8.8 dst=1.1.1.2 sport=53 dport=1 packets=1 bytes=90 mark=0\n')
    assert mod.flows(str(f)) == [('tcp', '10.0.0.2', '1.1.1.1', '40000', '443', 10000)]
    assert mod.flows(str(tmp_path / 'none')) == []


ETHTOOL = """Ring parameters for eth2:
Pre-set maximums:
RX:\t\t4096
RX Mini:\t0
RX Jumbo:\t0
TX:\t\t4096
Current hardware settings:
RX:\t\t256
RX Mini:\t0
RX Jumbo:\t0
TX:\t\t256
"""


def test_ring_parsing(mod):
    assert mod.parse_rings(ETHTOOL) == ({'rx': 4096, 'tx': 4096}, {'rx': 256, 'tx': 256})
    assert mod.parse_rings('Cannot get device ring settings: Operation not supported') == ({}, {})


def test_rings_are_raised_only_where_lower(mod, monkeypatch):
    calls = []

    class R:
        def __init__(self, out='', rc=0):
            self.stdout, self.returncode = out, rc

    def fake_run(cmd, stdin=None):
        calls.append(cmd)
        if cmd[:2] == ['ethtool', '-g']:
            if cmd[2] == 'eth0':
                return R(ETHTOOL.replace('RX:\t\t256', 'RX:\t\t4096').replace('TX:\t\t256', 'TX:\t\t4096'))
            if cmd[2] == 'eth9':
                return R('', 1)
            return R(ETHTOOL)
        return R()

    monkeypatch.setattr(mod, 'run', fake_run)
    monkeypatch.setattr(mod, 'syslog', lambda m: None)
    changed = mod.tune_rings(['eth0', 'eth2', 'eth9'])
    assert list(changed) == ['eth2']
    assert ['ethtool', '-G', 'eth2', 'rx', '4096', 'tx', '4096'] in calls
    assert not any(c[:3] == ['ethtool', '-G', 'eth0'] for c in calls)


@pytest.mark.parametrize('mem_mib,expected', [(256, 65536), (2048, 65536), (4096, 131072), (8192, 262144), (16384, 524288), (64000, 1048576)])
def test_conntrack_target(mod, mem_mib, expected):
    assert mod.conntrack_target(mem_mib * 1024) == expected


def test_conntrack_only_grows(mod, tmp_path, monkeypatch):
    monkeypatch.setattr(mod, 'syslog', lambda m: None)
    mem = tmp_path / 'meminfo'; mem.write_text('MemTotal:        8388608 kB\nMemFree: 1 kB\n')
    cmax = tmp_path / 'max'; cmax.write_text('65536\n')
    assert mod.tune_conntrack(str(mem), str(cmax)) == 262144
    assert cmax.read_text() == '262144'
    assert mod.tune_conntrack(str(mem), str(cmax)) is None            # nothing more to do
    cmax.write_text('600000\n')
    assert mod.tune_conntrack(str(mem), str(cmax)) is None            # never lowered
    assert cmax.read_text() == '600000\n'
    assert mod.tune_conntrack(str(tmp_path / 'none'), str(cmax)) is None


def test_snort_cpus_follow_the_hardware(mod, monkeypatch):
    calls, values = [], {'snort.nfq.queue_count': '4', 'snort.nfq.thread_count': '4'}

    class R:
        def __init__(self, rc=0, out=''):
            self.returncode, self.stdout = rc, out

    def fake_run(cmd, stdin=None):
        calls.append(cmd)
        if cmd[:3] == ['uci', '-q', 'get']:
            return R(0 if cmd[3] in ('snort.nfq', *values) else 1, values.get(cmd[3], ''))
        return R()

    monkeypatch.setattr(mod, 'run', fake_run)
    monkeypatch.setattr(mod, 'syslog', lambda m: None)
    monkeypatch.setattr(mod, 'uci_get', lambda c, s, o, d=None: values.get('%s.%s.%s' % (c, s, o), d))
    assert mod.tune_snort_cpus(16) == 16
    assert ['uci', 'set', 'snort.nfq.thread_count=16'] in calls and ['uci', 'commit', 'snort'] in calls
    calls.clear()
    assert mod.tune_snort_cpus(64) == 16                    # never above 16
    values['snort.nfq.queue_count'] = values['snort.nfq.thread_count'] = '16'
    calls.clear()
    assert mod.tune_snort_cpus(16) is None and not any(c[1] == 'set' for c in calls)
    values['snort.nfq.cpu_auto'] = '0'
    assert mod.tune_snort_cpus(2) is None                   # manual value kept


def test_cpu_count(mod, tmp_path):
    f = tmp_path / 'cpuinfo'; f.write_text('processor\t: 0\nmodel name: x\nprocessor\t: 1\n')
    assert mod.cpu_count(str(f)) == 2
    assert mod.cpu_count(str(tmp_path / 'none')) == 1
