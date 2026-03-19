import pytest
import sys
import os
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