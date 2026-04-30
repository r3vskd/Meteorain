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

def test_dnssec_do_bit_set():
    import spoof_engine
    from scapy.layers.dns import DNSRROPT
    from unittest.mock import patch
    captured = []
    with patch('spoof_engine.scapy_send', side_effect=lambda p, verbose: captured.append(p)):
        spoof_engine.send_spoofed_dns_query(
            domain='example.com', resolver_ip='8.8.8.8', resolver_port=53,
            victim_ip='1.2.3.4', edns_payload=512, dnssec_do=True)
    assert captured[0][DNSRROPT].z == 0x8000

def test_qtype_any_maps_to_255():
    import spoof_engine
    from scapy.layers.dns import DNSQR
    from unittest.mock import patch
    captured = []
    with patch('spoof_engine.scapy_send', side_effect=lambda p, verbose: captured.append(p)):
        spoof_engine.send_spoofed_dns_query(
            domain='example.com', resolver_ip='8.8.8.8', resolver_port=53,
            victim_ip='1.2.3.4', qtype='ANY', edns_payload=0)
    assert captured[0][DNSQR].qtype == 255

def test_qtype_dnskey_maps_to_48():
    import spoof_engine
    from scapy.layers.dns import DNSQR
    from unittest.mock import patch
    captured = []
    with patch('spoof_engine.scapy_send', side_effect=lambda p, verbose: captured.append(p)):
        spoof_engine.send_spoofed_dns_query(
            domain='example.com', resolver_ip='8.8.8.8', resolver_port=53,
            victim_ip='1.2.3.4', qtype='DNSKEY', edns_payload=0)
    assert captured[0][DNSQR].qtype == 48

def test_unknown_qtype_defaults_to_a():
    import spoof_engine
    from scapy.layers.dns import DNSQR
    from unittest.mock import patch
    captured = []
    with patch('spoof_engine.scapy_send', side_effect=lambda p, verbose: captured.append(p)):
        spoof_engine.send_spoofed_dns_query(
            domain='example.com', resolver_ip='8.8.8.8', resolver_port=53,
            victim_ip='1.2.3.4', qtype='BOGUS', edns_payload=0)
    assert captured[0][DNSQR].qtype == 1

def test_check_root_error_message_mentions_root(monkeypatch):
    import spoof_engine
    monkeypatch.setattr(spoof_engine, '_is_root', lambda: False)
    with pytest.raises(PermissionError) as exc_info:
        spoof_engine.check_root()
    assert 'root' in str(exc_info.value).lower()

def test_single_resolver_single_query():
    import spoof_engine
    from unittest.mock import patch
    sent = []
    with patch('spoof_engine.scapy_send', side_effect=lambda p, verbose: sent.append(p)):
        spoof_engine.send_spoofed_queries_through_resolvers(
            domain='example.com', resolvers=['1.1.1.1'], resolver_port=53,
            victim_ip='9.9.9.9', num_queries=1, burst=True)
    assert len(sent) == 1

def test_empty_resolver_list_returns_early():
    import spoof_engine
    from unittest.mock import patch
    sent = []
    with patch('spoof_engine.scapy_send', side_effect=lambda p, verbose: sent.append(p)):
        spoof_engine.send_spoofed_queries_through_resolvers(
            domain='example.com', resolvers=[], resolver_port=53,
            victim_ip='9.9.9.9')
    assert len(sent) == 0

def test_id_random_generates_varied_txids():
    import spoof_engine
    from scapy.layers.dns import DNS
    from unittest.mock import patch
    ids = []
    with patch('spoof_engine.scapy_send', side_effect=lambda p, verbose: ids.append(p[DNS].id)):
        for _ in range(20):
            spoof_engine.send_spoofed_dns_query(
                domain='example.com', resolver_ip='8.8.8.8', resolver_port=53,
                victim_ip='1.2.3.4', edns_payload=0, id_random=True)
    assert len(set(ids)) > 1

@pytest.mark.parametrize("qtype,expected", [
    ('A', 1), ('AAAA', 28), ('TXT', 16), ('MX', 15), ('NS', 2),
])
def test_qtype_wire_values(qtype, expected):
    import spoof_engine
    from scapy.layers.dns import DNSQR
    from unittest.mock import patch
    captured = []
    with patch('spoof_engine.scapy_send', side_effect=lambda p, verbose: captured.append(p)):
        spoof_engine.send_spoofed_dns_query(
            domain='example.com', resolver_ip='8.8.8.8', resolver_port=53,
            victim_ip='1.2.3.4', qtype=qtype, edns_payload=0)
    assert captured[0][DNSQR].qtype == expected