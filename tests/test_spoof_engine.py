import pytest
import sys
import os
import threading
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


def test_check_root_raises_on_non_root(monkeypatch):
    import spoof_engine
    monkeypatch.setattr(spoof_engine, '_is_root', lambda: False)
    with pytest.raises(PermissionError, match="root"):
        spoof_engine.check_root()


def test_check_root_passes_as_root(monkeypatch):
    import spoof_engine
    monkeypatch.setattr(spoof_engine, '_is_root', lambda: True)
    spoof_engine.check_root()


def test_send_spoofed_dns_query_calls_scapy_send():
    import spoof_engine
    sent = []
    with patch('spoof_engine.scapy_send', side_effect=lambda p, verbose: sent.append(p)):
        spoof_engine.send_spoofed_dns_query(
            domain='example.com', resolver_ip='8.8.8.8', resolver_port=53,
            victim_ip='1.2.3.4', victim_src_port=53, qtype='ANY',
            edns_payload=4096, txid=0x1337, id_random=False)
    assert len(sent) == 1


def test_victim_ip_is_packet_source():
    import spoof_engine
    from scapy.layers.inet import IP
    captured = []
    with patch('spoof_engine.scapy_send', side_effect=lambda p, verbose: captured.append(p)):
        spoof_engine.send_spoofed_dns_query(
            domain='example.com', resolver_ip='8.8.8.8', resolver_port=53,
            victim_ip='5.5.5.5', victim_src_port=53)
    assert captured[0][IP].src == '5.5.5.5'
    assert captured[0][IP].dst == '8.8.8.8'


def test_resolver_loop_fires_all_threads():
    import spoof_engine
    lock = threading.Lock()
    count = []
    def fake_send(p, verbose):
        with lock:
            count.append(1)
    with patch('spoof_engine.scapy_send', side_effect=fake_send):
        spoof_engine.send_spoofed_queries_through_resolvers(
            domain='example.com', resolvers=['1.1.1.1', '8.8.8.8'],
            resolver_port=53, victim_ip='1.2.3.4', num_queries=3,
            interval=0, burst=True)
    assert len(count) == 6


def test_burst_mode_skips_sleep():
    import spoof_engine
    sleeps = []
    with patch('spoof_engine.scapy_send', return_value=None), \
         patch('spoof_engine._time_sleep', side_effect=sleeps.append):
        spoof_engine.send_spoofed_queries_through_resolvers(
            domain='example.com', resolvers=['1.1.1.1'],
            resolver_port=53, victim_ip='1.2.3.4',
            num_queries=2, interval=0.01, burst=True)
    assert len(sleeps) == 0

def test_edns_payload_sets_opt_rclass():
    import spoof_engine
    from scapy.layers.dns import DNSRROPT
    captured = []
    from unittest.mock import patch
    with patch('spoof_engine.scapy_send', side_effect=lambda p, verbose: captured.append(p)):
        spoof_engine.send_spoofed_dns_query(
            domain='example.com', resolver_ip='8.8.8.8', resolver_port=53,
            victim_ip='1.2.3.4', edns_payload=4096)
    pkt = captured[0]
    assert pkt.haslayer(DNSRROPT)
    assert pkt[DNSRROPT].rclass == 4096