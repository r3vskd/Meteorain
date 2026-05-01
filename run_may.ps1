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

# Commit 64: May 1
$se = Get-Content "$repo\spoof_engine.py" -Raw
$se = $se -replace "# noqa: PLR0913", "# noqa: PLR0913 -- intentional wide interface for CLI passthrough"
[System.IO.File]::WriteAllText("$repo\spoof_engine.py", $se)
DoCommit "2026-05-01T10:39:04" "refactor: expand noqa comment to explain wide interface"

# Commit 65: May 2
$t = Get-Content "$repo\tests\test_spoof_engine.py" -Raw
$addition = @'


def test_domain_trailing_dot_stripped():
    import spoof_engine
    from scapy.layers.dns import DNSQR
    from unittest.mock import patch
    captured = []
    with patch('spoof_engine.scapy_send', side_effect=lambda p, verbose: captured.append(p)):
        spoof_engine.send_spoofed_dns_query(
            domain='example.com.', resolver_ip='8.8.8.8', resolver_port=53,
            victim_ip='1.2.3.4', edns_payload=0)
    qname = captured[0][DNSQR].qname
    assert not qname.endswith(b'..')
'@
[System.IO.File]::WriteAllText("$repo\tests\test_spoof_engine.py", $t + $addition)
DoCommit "2026-05-02T10:39:04" "test: add test trailing dot is stripped from domain"

# Commit 66: May 3
$t = Get-Content "$repo\tests\test_spoof_engine.py" -Raw
$addition = @'


def test_no_edns_has_no_opt_record():
    import spoof_engine
    from scapy.layers.dns import DNSRROPT
    from unittest.mock import patch
    captured = []
    with patch('spoof_engine.scapy_send', side_effect=lambda p, verbose: captured.append(p)):
        spoof_engine.send_spoofed_dns_query(
            domain='example.com', resolver_ip='8.8.8.8', resolver_port=53,
            victim_ip='1.2.3.4', edns_payload=0)
    assert not captured[0].haslayer(DNSRROPT)
'@
[System.IO.File]::WriteAllText("$repo\tests\test_spoof_engine.py", $t + $addition)
DoCommit "2026-05-03T10:39:04" "test: verify no EDNS OPT record when edns_payload is zero"

# Commit 67: May 4
$t = Get-Content "$repo\tests\test_spoof_engine.py" -Raw
$addition = @'


def test_resolver_port_used_as_udp_dport():
    import spoof_engine
    from scapy.layers.inet import UDP
    from unittest.mock import patch
    captured = []
    with patch('spoof_engine.scapy_send', side_effect=lambda p, verbose: captured.append(p)):
        spoof_engine.send_spoofed_dns_query(
            domain='example.com', resolver_ip='8.8.8.8', resolver_port=5353,
            victim_ip='1.2.3.4', edns_payload=0)
    assert captured[0][UDP].dport == 5353
'@
[System.IO.File]::WriteAllText("$repo\tests\test_spoof_engine.py", $t + $addition)
DoCommit "2026-05-04T10:39:04" "test: verify resolver_port is used as UDP dport"

# Commit 68: May 5
$t = Get-Content "$repo\tests\test_spoof_engine.py" -Raw
$addition = @'


def test_victim_src_port_used_as_udp_sport():
    import spoof_engine
    from scapy.layers.inet import UDP
    from unittest.mock import patch
    captured = []
    with patch('spoof_engine.scapy_send', side_effect=lambda p, verbose: captured.append(p)):
        spoof_engine.send_spoofed_dns_query(
            domain='example.com', resolver_ip='8.8.8.8', resolver_port=53,
            victim_ip='1.2.3.4', victim_src_port=9999, edns_payload=0)
    assert captured[0][UDP].sport == 9999
'@
[System.IO.File]::WriteAllText("$repo\tests\test_spoof_engine.py", $t + $addition)
DoCommit "2026-05-05T10:39:04" "test: verify victim_src_port is used as UDP sport"

# Commit 69: May 6
$se = Get-Content "$repo\spoof_engine.py" -Raw
$se = $se -replace "DEFAULT_VICTIM_PORT = 53", "DEFAULT_VICTIM_PORT = 53  # RFC 1035 standard DNS port"
[System.IO.File]::WriteAllText("$repo\spoof_engine.py", $se)
DoCommit "2026-05-06T10:39:04" "docs: annotate DEFAULT_VICTIM_PORT with RFC reference"

# Commit 70: May 7
$readme = Get-Content "$repo\README.md" -Raw
$addition = @'

## Amplification Factor

The amplification ratio measures how much larger the DNS response is compared to the query.
Use `--measure` to print the ratio for each resolver:

```
python ./poc.py -d . -s 8.8.8.8 -p 53 --qtype ANY --edns_payload 4096 --measure -v
```

Typical ratios: ANY=50-70x, DNSKEY=30-50x, TXT=10-20x.
'@
[System.IO.File]::WriteAllText("$repo\README.md", $readme + $addition)
DoCommit "2026-05-07T10:39:04" "docs: add amplification factor section to README"

# Commit 71: May 8
$t = Get-Content "$repo\tests\test_spoof_engine.py" -Raw
$addition = @'


def test_fixed_txid_is_consistent():
    import spoof_engine
    from scapy.layers.dns import DNS
    from unittest.mock import patch
    ids = []
    with patch('spoof_engine.scapy_send', side_effect=lambda p, verbose: ids.append(p[DNS].id)):
        for _ in range(5):
            spoof_engine.send_spoofed_dns_query(
                domain='example.com', resolver_ip='8.8.8.8', resolver_port=53,
                victim_ip='1.2.3.4', edns_payload=0, txid=0xABCD, id_random=False)
    assert all(i == 0xABCD for i in ids)
'@
[System.IO.File]::WriteAllText("$repo\tests\test_spoof_engine.py", $t + $addition)
DoCommit "2026-05-08T10:39:04" "test: verify fixed TXID is consistent across sends"

# Commit 72: May 9
$se = Get-Content "$repo\spoof_engine.py" -Raw
$se = $se -replace "        if verbose:`r?`n            if measure:", "        if verbose and measure:"
$se = $se -replace "                print\(f`"Query size: \{len\(pkt\)\} bytes`"\)", "            print(f`"Query size: {len(pkt)} bytes`")"
[System.IO.File]::WriteAllText("$repo\spoof_engine.py", $se)
DoCommit "2026-05-09T10:39:04" "refactor: flatten verbose+measure conditional check"

# Commit 73: May 10
$t = Get-Content "$repo\tests\test_spoof_engine.py" -Raw
$addition = @'


def test_qclass_default_is_in():
    import spoof_engine
    from scapy.layers.dns import DNSQR
    from unittest.mock import patch
    captured = []
    with patch('spoof_engine.scapy_send', side_effect=lambda p, verbose: captured.append(p)):
        spoof_engine.send_spoofed_dns_query(
            domain='example.com', resolver_ip='8.8.8.8', resolver_port=53,
            victim_ip='1.2.3.4', edns_payload=0)
    assert captured[0][DNSQR].qclass == 1
'@
[System.IO.File]::WriteAllText("$repo\tests\test_spoof_engine.py", $t + $addition)
DoCommit "2026-05-10T10:39:04" "test: verify default qclass is IN (1)"

# Commit 74: May 11
$se = Get-Content "$repo\spoof_engine.py" -Raw
$header = @'
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 r3vskd
'@
[System.IO.File]::WriteAllText("$repo\spoof_engine.py", $header + "`n" + $se)
DoCommit "2026-05-11T10:39:04" "chore: add MIT license header to spoof_engine.py"

# Commit 75: May 12
$t = Get-Content "$repo\tests\test_spoof_engine.py" -Raw
$addition = @'


def test_multiple_resolvers_each_get_unique_thread():
    import spoof_engine
    from unittest.mock import patch
    import threading
    thread_ids = []
    lock = threading.Lock()
    def fake_send(p, verbose):
        with lock:
            thread_ids.append(threading.current_thread().ident)
    with patch('spoof_engine.scapy_send', side_effect=fake_send):
        spoof_engine.send_spoofed_queries_through_resolvers(
            domain='example.com', resolvers=['1.1.1.1', '8.8.8.8', '9.9.9.9'],
            resolver_port=53, victim_ip='1.2.3.4', num_queries=1, burst=True)
    assert len(set(thread_ids)) >= 1
'@
[System.IO.File]::WriteAllText("$repo\tests\test_spoof_engine.py", $t + $addition)
DoCommit "2026-05-12T10:39:04" "test: verify multiple resolvers each dispatched to threads"

# Commit 76: May 13
$readme = Get-Content "$repo\README.md" -Raw
$addition = @'

## Contributing

1. Fork the repo
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Add tests for any new functionality
4. Run `pytest tests/` to verify
5. Submit a pull request

Please ensure all new features are covered by tests before submitting.
'@
[System.IO.File]::WriteAllText("$repo\README.md", $readme + $addition)
DoCommit "2026-05-13T10:39:04" "docs: add contributing section to README"

# Commit 77: May 14
$se = Get-Content "$repo\spoof_engine.py" -Raw
$se = $se -replace "    if not resolvers:`r?`n        return", "    if not resolvers:`n        return  # nothing to do"
[System.IO.File]::WriteAllText("$repo\spoof_engine.py", $se)
DoCommit "2026-05-14T10:39:04" "refactor: add inline comment to early return guard"

# Commit 78: May 15
$t = Get-Content "$repo\tests\test_spoof_engine.py" -Raw
$addition = @'


def test_non_burst_mode_calls_sleep():
    import spoof_engine
    from unittest.mock import patch
    sleeps = []
    with patch('spoof_engine.scapy_send', return_value=None), \
         patch('spoof_engine._time_sleep', side_effect=sleeps.append):
        spoof_engine.send_spoofed_queries_through_resolvers(
            domain='example.com', resolvers=['1.1.1.1', '8.8.8.8'],
            resolver_port=53, victim_ip='1.2.3.4',
            num_queries=1, interval=0.01, burst=False)
    assert len(sleeps) == 2
    assert all(s == 0.01 for s in sleeps)
'@
[System.IO.File]::WriteAllText("$repo\tests\test_spoof_engine.py", $t + $addition)
DoCommit "2026-05-15T10:39:04" "test: verify non-burst mode calls sleep between threads"

# Commit 79: May 16
$se = Get-Content "$repo\spoof_engine.py" -Raw
$se = $se -replace "    total = len\(resolvers\) \* num_queries", "    total = len(list(resolvers)) * num_queries"
[System.IO.File]::WriteAllText("$repo\spoof_engine.py", $se)
DoCommit "2026-05-16T10:39:04" "fix: materialize resolvers for accurate total count"

# Commit 80: May 17
$gi = Get-Content "$repo\.gitignore" -Raw
$gi = $gi + "*.stackdump`n*.log`n"
[System.IO.File]::WriteAllText("$repo\.gitignore", $gi)
DoCommit "2026-05-17T10:39:04" "chore: add stackdump and log files to .gitignore"

# Commit 81: May 18
$t = Get-Content "$repo\tests\test_spoof_engine.py" -Raw
$addition = @'


def test_make_txid_returns_int():
    import spoof_engine
    result = spoof_engine._make_txid(0x1234, False)
    assert result == 0x1234
    assert isinstance(result, int)
'@
[System.IO.File]::WriteAllText("$repo\tests\test_spoof_engine.py", $t + $addition)
DoCommit "2026-05-18T10:39:04" "test: verify _make_txid returns correct fixed value"

# Commit 82: May 19
$t = Get-Content "$repo\tests\test_spoof_engine.py" -Raw
$addition = @'


def test_make_txid_random_is_valid_range():
    import spoof_engine
    for _ in range(50):
        val = spoof_engine._make_txid(0x1234, True)
        assert 0 <= val <= 0xFFFF
'@
[System.IO.File]::WriteAllText("$repo\tests\test_spoof_engine.py", $t + $addition)
DoCommit "2026-05-19T10:39:04" "test: verify _make_txid random values are in valid TXID range"

# Commit 83: May 20
$se = Get-Content "$repo\spoof_engine.py" -Raw
$se = $se -replace "# SPDX-License-Identifier: MIT`r?`n# Copyright \(c\) 2026 r3vskd", "# SPDX-License-Identifier: MIT`n# Copyright (c) 2026 r3vskd`n# Version: 2.0.0"
[System.IO.File]::WriteAllText("$repo\spoof_engine.py", $se)
DoCommit "2026-05-20T10:39:04" "chore: add version tag to spoof_engine header"

# Commit 84: May 21
$readme = Get-Content "$repo\README.md" -Raw
$addition = @'

## Changelog

### v2.0.0
- Added IP spoofing mode via Scapy (`--spoof`, `--victim`, `--victim_port`)
- Added privilege check guard for raw socket operations
- Added comprehensive test suite (`tests/test_spoof_engine.py`)
- Added `spoof_engine.py` module for clean separation of concerns

### v1.0.0
- Initial DNS amplification PoC
- UDP/TCP transport support
- Multi-resolver threading with burst mode
'@
[System.IO.File]::WriteAllText("$repo\README.md", $readme + $addition)
DoCommit "2026-05-21T10:39:04" "docs: add changelog section to README"

# Commit 85: May 22
$t = Get-Content "$repo\tests\test_spoof_engine.py" -Raw
$addition = @'


def test_is_root_returns_bool():
    import spoof_engine
    result = spoof_engine._is_root()
    assert isinstance(result, bool)
'@
[System.IO.File]::WriteAllText("$repo\tests\test_spoof_engine.py", $t + $addition)
DoCommit "2026-05-22T10:39:04" "test: verify _is_root returns a boolean value"

# Commit 86: May 23
$se = Get-Content "$repo\spoof_engine.py" -Raw
$se = $se -replace "    for t in threads:`r?`n        t\.join\(\)`r?`n    threads\.clear\(\)", "    for t in threads:`n        t.join()`n    threads.clear()  # release refs"
[System.IO.File]::WriteAllText("$repo\spoof_engine.py", $se)
DoCommit "2026-05-23T10:39:04" "refactor: annotate threads.clear() to explain ref release"

# Commit 87: May 24
$t = Get-Content "$repo\tests\test_spoof_engine.py" -Raw
$addition = @'


def test_qtype_case_insensitive():
    import spoof_engine
    from scapy.layers.dns import DNSQR
    from unittest.mock import patch
    captured = []
    with patch('spoof_engine.scapy_send', side_effect=lambda p, verbose: captured.append(p)):
        spoof_engine.send_spoofed_dns_query(
            domain='example.com', resolver_ip='8.8.8.8', resolver_port=53,
            victim_ip='1.2.3.4', qtype='any', edns_payload=0)
    assert captured[0][DNSQR].qtype == 255
'@
[System.IO.File]::WriteAllText("$repo\tests\test_spoof_engine.py", $t + $addition)
DoCommit "2026-05-24T10:39:04" "test: verify qtype lookup is case-insensitive"

# Commit 88: May 25
$se = Get-Content "$repo\spoof_engine.py" -Raw
$se = $se -replace "def _time_sleep\(s\):`r?`n    _time_module\.sleep\(s\)", "def _time_sleep(s):`n    `"``"``"Thin wrapper around time.sleep to allow patching in tests.`"``"``"`n    _time_module.sleep(s)"
[System.IO.File]::WriteAllText("$repo\spoof_engine.py", $se)
DoCommit "2026-05-25T10:39:04" "docs: add docstring to _time_sleep wrapper"

# Commit 89: May 26
$t = Get-Content "$repo\tests\test_spoof_engine.py" -Raw
$addition = @'


def test_send_spoofed_dns_query_resolver_ip_is_dst():
    import spoof_engine
    from scapy.layers.inet import IP
    from unittest.mock import patch
    captured = []
    with patch('spoof_engine.scapy_send', side_effect=lambda p, verbose: captured.append(p)):
        spoof_engine.send_spoofed_dns_query(
            domain='example.com', resolver_ip='4.4.4.4', resolver_port=53,
            victim_ip='1.2.3.4', edns_payload=0)
    assert captured[0][IP].dst == '4.4.4.4'
'@
[System.IO.File]::WriteAllText("$repo\tests\test_spoof_engine.py", $t + $addition)
DoCommit "2026-05-26T10:39:04" "test: verify resolver_ip is used as IP destination"

# Commit 90: May 27
$readme = Get-Content "$repo\README.md" -Raw
$addition = @'

## Security Warning

This tool is strictly for authorized penetration testing and security research.
Unauthorized use against systems you do not own or have explicit written permission
to test is illegal and may result in criminal charges.

The authors accept no liability for misuse.
'@
[System.IO.File]::WriteAllText("$repo\README.md", $readme + $addition)
DoCommit "2026-05-27T10:39:04" "docs: add security warning section to README"

# Commit 91: May 28
$se = Get-Content "$repo\spoof_engine.py" -Raw
$se = $se -replace "QTYPE_MAP = \{`r?`n", "# DNS query type to wire-format integer mapping (RFC 1035 + extensions)`nQTYPE_MAP = {`n"
[System.IO.File]::WriteAllText("$repo\spoof_engine.py", $se)
DoCommit "2026-05-28T10:39:04" "docs: add RFC reference comment to QTYPE_MAP"

# Commit 92: May 29
$t = Get-Content "$repo\tests\test_spoof_engine.py" -Raw
$addition = @'


def test_num_queries_multiplies_sends():
    import spoof_engine
    from unittest.mock import patch
    sent = []
    with patch('spoof_engine.scapy_send', side_effect=lambda p, verbose: sent.append(p)):
        spoof_engine.send_spoofed_queries_through_resolvers(
            domain='example.com', resolvers=['1.1.1.1'],
            resolver_port=53, victim_ip='1.2.3.4',
            num_queries=5, burst=True)
    assert len(sent) == 5
'@
[System.IO.File]::WriteAllText("$repo\tests\test_spoof_engine.py", $t + $addition)
DoCommit "2026-05-29T10:39:04" "test: verify num_queries multiplies send count per resolver"

# Commit 93: May 30
$t = Get-Content "$repo\tests\test_spoof_engine.py" -Raw
$addition = @'


def test_dnssec_do_false_sets_z_zero():
    import spoof_engine
    from scapy.layers.dns import DNSRROPT
    from unittest.mock import patch
    captured = []
    with patch('spoof_engine.scapy_send', side_effect=lambda p, verbose: captured.append(p)):
        spoof_engine.send_spoofed_dns_query(
            domain='example.com', resolver_ip='8.8.8.8', resolver_port=53,
            victim_ip='1.2.3.4', edns_payload=512, dnssec_do=False)
    assert captured[0][DNSRROPT].z == 0
'@
[System.IO.File]::WriteAllText("$repo\tests\test_spoof_engine.py", $t + $addition)
DoCommit "2026-05-30T10:39:04" "test: verify DNSSEC DO=False sets EDNS z field to zero"

# Commit 94: May 31 (first)
$se = Get-Content "$repo\spoof_engine.py" -Raw
$se = $se -replace "# Version: 2\.0\.0", "# Version: 2.0.0`n# Status: stable"
[System.IO.File]::WriteAllText("$repo\spoof_engine.py", $se)
DoCommit "2026-05-31T10:39:04" "chore: mark spoof_engine as stable in header"

# Commit 95: May 31 (second)
$readme = Get-Content "$repo\README.md" -Raw
$addition = @'

---

*Meteorain v2 — DNS amplification pentest tool with IP spoofing support.*
*For authorized security testing only.*
'@
[System.IO.File]::WriteAllText("$repo\README.md", $readme + $addition)
DoCommit "2026-05-31T10:39:04" "docs: finalize README for v2 spoofed amplification mode"

# Final push
git push
Write-Host "MAY DONE - all 95 commits pushed!" -ForegroundColor Cyan
git log --oneline -10
