import pytest


@pytest.fixture(autouse=False)
def no_scapy_send(monkeypatch):
    """Fixture to stub out scapy_send in tests that need it."""
    import spoof_engine
    sent = []
    monkeypatch.setattr(spoof_engine, 'scapy_send', lambda p, verbose=False: sent.append(p))
    return sent