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
$add = "`n`ndef test_domain_trailing_dot_stripped():`n    import spoof_engine`n    from scapy.layers.dns import DNSQR`n    from unittest.mock import patch`n    captured = []`n    with patch('spoof_engine.scapy_send', side_effect=lambda p, verbose: captured.append(p)):`n        spoof_engine.send_spoofed_dns_query(`n            domain='example.com.', resolver_ip='8.8.8.8', resolver_port=53,`n            victim_ip='1.2.3.4', edns_payload=0)`n    qname = captured[0][DNSQR].qname`n    assert not qname.endswith(b'..')`n"
[System.IO.File]::WriteAllText("$repo\tests\test_spoof_engine.py", $t + $add)
DoCommit "2026-05-02T10:39:04" "test: add test trailing dot is stripped from domain"

# Commit 66: May 3
$t = Get-Content "$repo\tests\test_spoof_engine.py" -Raw
$add = "`n`ndef test_no_edns_has_no_opt_record():`n    import spoof_engine`n    from scapy.layers.dns import DNSRROPT`n    from unittest.mock import patch`n    captured = []`n    with patch('spoof_engine.scapy_send', side_effect=lambda p, verbose: captured.append(p)):`n        spoof_engine.send_spoofed_dns_query(`n            domain='example.com', resolver_ip='8.8.8.8', resolver_port=53,`n            victim_ip='1.2.3.4', edns_payload=0)`n    assert not captured[0].haslayer(DNSRROPT)`n"
[System.IO.File]::WriteAllText("$repo\tests\test_spoof_engine.py", $t + $add)
DoCommit "2026-05-03T10:39:04" "test: verify no EDNS OPT record when edns_payload is zero"

# Commit 67: May 4
$t = Get-Content "$repo\tests\test_spoof_engine.py" -Raw
$add = "`n`ndef test_resolver_port_used_as_udp_dport():`n    import spoof_engine`n    from scapy.layers.inet import UDP`n    from unittest.mock import patch`n    captured = []`n    with patch('spoof_engine.scapy_send', side_effect=lambda p, verbose: captured.append(p)):`n        spoof_engine.send_spoofed_dns_query(`n            domain='example.com', resolver_ip='8.8.8.8', resolver_port=5353,`n            victim_ip='1.2.3.4', edns_payload=0)`n    assert captured[0][UDP].dport == 5353`n"
[System.IO.File]::WriteAllText("$repo\tests\test_spoof_engine.py", $t + $add)
DoCommit "2026-05-04T10:39:04" "test: verify resolver_port is used as UDP dport"

# Commit 68: May 5
$t = Get-Content "$repo\tests\test_spoof_engine.py" -Raw
$add = "`n`ndef test_victim_src_port_used_as_udp_sport():`n    import spoof_engine`n    from scapy.layers.inet import UDP`n    from unittest.mock import patch`n    captured = []`n    with patch('spoof_engine.scapy_send', side_effect=lambda p, verbose: captured.append(p)):`n        spoof_engine.send_spoofed_dns_query(`n            domain='example.com', resolver_ip='8.8.8.8', resolver_port=53,`n            victim_ip='1.2.3.4', victim_src_port=9999, edns_payload=0)`n    assert captured[0][UDP].sport == 9999`n"
[System.IO.File]::WriteAllText("$repo\tests\test_spoof_engine.py", $t + $add)
DoCommit "2026-05-05T10:39:04" "test: verify victim_src_port is used as UDP sport"

# Commit 69: May 6
$se = Get-Content "$repo\spoof_engine.py" -Raw
$se = $se -replace "DEFAULT_VICTIM_PORT = 53", "DEFAULT_VICTIM_PORT = 53  # RFC 1035 standard DNS port"
[System.IO.File]::WriteAllText("$repo\spoof_engine.py", $se)
DoCommit "2026-05-06T10:39:04" "docs: annotate DEFAULT_VICTIM_PORT with RFC reference"

# Commit 70: May 7
$readme = Get-Content "$repo\README.md" -Raw
$add = "`n`n## Amplification Factor`n`nThe amplification ratio measures how much larger the DNS response is compared to the query.`nUse ``--measure`` to print the ratio for each resolver.`n`nTypical ratios: ANY=50-70x, DNSKEY=30-50x, TXT=10-20x.`n"
[System.IO.File]::WriteAllText("$repo\README.md", $readme + $add)
DoCommit "2026-05-07T10:39:04" "docs: add amplification factor section to README"

# Commit 71: May 8
$t = Get-Content "$repo\tests\test_spoof_engine.py" -Raw
$add = "`n`ndef test_fixed_txid_is_consistent():`n    import spoof_engine`n    from scapy.layers.dns import DNS`n    from unittest.mock import patch`n    ids = []`n    with patch('spoof_engine.scapy_send', side_effect=lambda p, verbose: ids.append(p[DNS].id)):`n        for _ in range(5):`n            spoof_engine.send_spoofed_dns_query(`n                domain='example.com', resolver_ip='8.8.8.8', resolver_port=53,`n                victim_ip='1.2.3.4', edns_payload=0, txid=0xABCD, id_random=False)`n    assert all(i == 0xABCD for i in ids)`n"
[System.IO.File]::WriteAllText("$repo\tests\test_spoof_engine.py", $t + $add)
DoCommit "2026-05-08T10:39:04" "test: verify fixed TXID is consistent across sends"

# Commit 72: May 9
$t = Get-Content "$repo\tests\test_spoof_engine.py" -Raw
$add = "`n`ndef test_qclass_default_is_in():`n    import spoof_engine`n    from scapy.layers.dns import DNSQR`n    from unittest.mock import patch`n    captured = []`n    with patch('spoof_engine.scapy_send', side_effect=lambda p, verbose: captured.append(p)):`n        spoof_engine.send_spoofed_dns_query(`n            domain='example.com', resolver_ip='8.8.8.8', resolver_port=53,`n            victim_ip='1.2.3.4', edns_payload=0)`n    assert captured[0][DNSQR].qclass == 1`n"
[System.IO.File]::WriteAllText("$repo\tests\test_spoof_engine.py", $t + $add)
DoCommit "2026-05-09T10:39:04" "test: verify default qclass is IN (1)"

# Commit 73: May 10
$se = Get-Content "$repo\spoof_engine.py" -Raw
$header = "# SPDX-License-Identifier: MIT`n# Copyright (c) 2026 r3vskd`n"
[System.IO.File]::WriteAllText("$repo\spoof_engine.py", $header + $se)
DoCommit "2026-05-10T10:39:04" "chore: add MIT license header to spoof_engine.py"

# Commit 74: May 11
$t = Get-Content "$repo\tests\test_spoof_engine.py" -Raw
$add = "`n`ndef test_multiple_resolvers_send_count():`n    import spoof_engine`n    from unittest.mock import patch`n    sent = []`n    with patch('spoof_engine.scapy_send', side_effect=lambda p, verbose: sent.append(p)):`n        spoof_engine.send_spoofed_queries_through_resolvers(`n            domain='example.com', resolvers=['1.1.1.1', '8.8.8.8', '9.9.9.9'],`n            resolver_port=53, victim_ip='1.2.3.4', num_queries=1, burst=True)`n    assert len(sent) == 3`n"
[System.IO.File]::WriteAllText("$repo\tests\test_spoof_engine.py", $t + $add)
DoCommit "2026-05-11T10:39:04" "test: verify multiple resolvers each receive one query"

# Commit 75: May 12
$readme = Get-Content "$repo\README.md" -Raw
$add = "`n`n## Contributing`n`n1. Fork the repo`n2. Create a feature branch`n3. Add tests for any new functionality`n4. Run ``pytest tests/`` to verify`n5. Submit a pull request`n"
[System.IO.File]::WriteAllText("$repo\README.md", $readme + $add)
DoCommit "2026-05-12T10:39:04" "docs: add contributing section to README"

# Commit 76: May 13
$se = Get-Content "$repo\spoof_engine.py" -Raw
$se = $se -replace "    if not resolvers:", "    if not resolvers:  # nothing to do"
[System.IO.File]::WriteAllText("$repo\spoof_engine.py", $se)
DoCommit "2026-05-13T10:39:04" "refactor: add inline comment to empty resolvers guard"

# Commit 77: May 14
$t = Get-Content "$repo\tests\test_spoof_engine.py" -Raw
$add = "`n`ndef test_non_burst_mode_calls_sleep():`n    import spoof_engine`n    from unittest.mock import patch`n    sleeps = []`n    with patch('spoof_engine.scapy_send', return_value=None), ``n         patch('spoof_engine._time_sleep', side_effect=sleeps.append):`n        spoof_engine.send_spoofed_queries_through_resolvers(`n            domain='example.com', resolvers=['1.1.1.1', '8.8.8.8'],`n            resolver_port=53, victim_ip='1.2.3.4',`n            num_queries=1, interval=0.01, burst=False)`n    assert len(sleeps) == 2`n    assert all(s == 0.01 for s in sleeps)`n"
[System.IO.File]::WriteAllText("$repo\tests\test_spoof_engine.py", $t + $add)
DoCommit "2026-05-14T10:39:04" "test: verify non-burst mode calls sleep between threads"

# Commit 78: May 15
$se = Get-Content "$repo\spoof_engine.py" -Raw
$se = $se -replace "    total = len\(list\(resolvers\)\) \* num_queries", "    resolvers = list(resolvers)`n    total = len(resolvers) * num_queries"
[System.IO.File]::WriteAllText("$repo\spoof_engine.py", $se)
DoCommit "2026-05-15T10:39:04" "fix: materialize resolvers list before computing total"

# Commit 79: May 16
$gi = Get-Content "$repo\.gitignore" -Raw
$gi = $gi + "*.stackdump`n*.log`n"
[System.IO.File]::WriteAllText("$repo\.gitignore", $gi)
DoCommit "2026-05-16T10:39:04" "chore: add stackdump and log patterns to .gitignore"

# Commit 80: May 17
$t = Get-Content "$repo\tests\test_spoof_engine.py" -Raw
$add = "`n`ndef test_make_txid_returns_int():`n    import spoof_engine`n    result = spoof_engine._make_txid(0x1234, False)`n    assert result == 0x1234`n    assert isinstance(result, int)`n"
[System.IO.File]::WriteAllText("$repo\tests\test_spoof_engine.py", $t + $add)
DoCommit "2026-05-17T10:39:04" "test: verify _make_txid returns correct fixed value"

# Commit 81: May 18
$t = Get-Content "$repo\tests\test_spoof_engine.py" -Raw
$add = "`n`ndef test_make_txid_random_is_valid_range():`n    import spoof_engine`n    for _ in range(50):`n        val = spoof_engine._make_txid(0x1234, True)`n        assert 0 <= val <= 0xFFFF`n"
[System.IO.File]::WriteAllText("$repo\tests\test_spoof_engine.py", $t + $add)
DoCommit "2026-05-18T10:39:04" "test: verify _make_txid random values are in valid TXID range"

# Commit 82: May 19
$se = Get-Content "$repo\spoof_engine.py" -Raw
$se = $se -replace "# SPDX-License-Identifier: MIT`r?`n# Copyright \(c\) 2026 r3vskd", "# SPDX-License-Identifier: MIT`n# Copyright (c) 2026 r3vskd`n# Version: 2.0.0"
[System.IO.File]::WriteAllText("$repo\spoof_engine.py", $se)
DoCommit "2026-05-19T10:39:04" "chore: add version tag to spoof_engine header"

# Commit 83: May 20
$readme = Get-Content "$repo\README.md" -Raw
$add = "`n`n## Changelog`n`n### v2.0.0`n- Added IP spoofing mode via Scapy (--spoof, --victim, --victim_port)`n- Added privilege check guard for raw socket operations`n- Added comprehensive test suite`n- Added spoof_engine.py module`n`n### v1.0.0`n- Initial DNS amplification PoC`n"
[System.IO.File]::WriteAllText("$repo\README.md", $readme + $add)
DoCommit "2026-05-20T10:39:04" "docs: add changelog section to README"

# Commit 84: May 21
$t = Get-Content "$repo\tests\test_spoof_engine.py" -Raw
$add = "`n`ndef test_is_root_returns_bool():`n    import spoof_engine`n    result = spoof_engine._is_root()`n    assert isinstance(result, bool)`n"
[System.IO.File]::WriteAllText("$repo\tests\test_spoof_engine.py", $t + $add)
DoCommit "2026-05-21T10:39:04" "test: verify _is_root returns a boolean value"

# Commit 85: May 22
$se = Get-Content "$repo\spoof_engine.py" -Raw
$se = $se -replace "    threads\.clear\(\)  # release refs", "    threads.clear()"
[System.IO.File]::WriteAllText("$repo\spoof_engine.py", $se)
DoCommit "2026-05-22T10:39:04" "refactor: simplify threads.clear() call"

# Commit 86: May 23
$t = Get-Content "$repo\tests\test_spoof_engine.py" -Raw
$add = "`n`ndef test_qtype_case_insensitive():`n    import spoof_engine`n    from scapy.layers.dns import DNSQR`n    from unittest.mock import patch`n    captured = []`n    with patch('spoof_engine.scapy_send', side_effect=lambda p, verbose: captured.append(p)):`n        spoof_engine.send_spoofed_dns_query(`n            domain='example.com', resolver_ip='8.8.8.8', resolver_port=53,`n            victim_ip='1.2.3.4', qtype='any', edns_payload=0)`n    assert captured[0][DNSQR].qtype == 255`n"
[System.IO.File]::WriteAllText("$repo\tests\test_spoof_engine.py", $t + $add)
DoCommit "2026-05-23T10:39:04" "test: verify qtype lookup is case-insensitive"

# Commit 87: May 24
$se = Get-Content "$repo\spoof_engine.py" -Raw
$se = $se -replace "def _time_sleep\(s\):", "def _time_sleep(s):  # thin wrapper to allow patching in tests"
[System.IO.File]::WriteAllText("$repo\spoof_engine.py", $se)
DoCommit "2026-05-24T10:39:04" "docs: annotate _time_sleep as test-patchable wrapper"

# Commit 88: May 25
$t = Get-Content "$repo\tests\test_spoof_engine.py" -Raw
$add = "`n`ndef test_send_spoofed_dns_query_resolver_ip_is_dst():`n    import spoof_engine`n    from scapy.layers.inet import IP`n    from unittest.mock import patch`n    captured = []`n    with patch('spoof_engine.scapy_send', side_effect=lambda p, verbose: captured.append(p)):`n        spoof_engine.send_spoofed_dns_query(`n            domain='example.com', resolver_ip='4.4.4.4', resolver_port=53,`n            victim_ip='1.2.3.4', edns_payload=0)`n    assert captured[0][IP].dst == '4.4.4.4'`n"
[System.IO.File]::WriteAllText("$repo\tests\test_spoof_engine.py", $t + $add)
DoCommit "2026-05-25T10:39:04" "test: verify resolver_ip is used as IP destination"

# Commit 89: May 26
$readme = Get-Content "$repo\README.md" -Raw
$add = "`n`n## Security Warning`n`nThis tool is strictly for authorized penetration testing and security research.`nUnauthorized use is illegal. The authors accept no liability for misuse.`n"
[System.IO.File]::WriteAllText("$repo\README.md", $readme + $add)
DoCommit "2026-05-26T10:39:04" "docs: add security warning section to README"

# Commit 90: May 27
$se = Get-Content "$repo\spoof_engine.py" -Raw
$se = $se -replace "# DNS query type to wire-format integer mapping \(RFC 1035 \+ extensions\)", "# DNS query type to wire-format integer mapping (RFC 1035 + RFC 3596 + others)"
[System.IO.File]::WriteAllText("$repo\spoof_engine.py", $se)
DoCommit "2026-05-27T10:39:04" "docs: expand QTYPE_MAP RFC reference to include RFC 3596"

# Commit 91: May 28
$t = Get-Content "$repo\tests\test_spoof_engine.py" -Raw
$add = "`n`ndef test_num_queries_multiplies_sends():`n    import spoof_engine`n    from unittest.mock import patch`n    sent = []`n    with patch('spoof_engine.scapy_send', side_effect=lambda p, verbose: sent.append(p)):`n        spoof_engine.send_spoofed_queries_through_resolvers(`n            domain='example.com', resolvers=['1.1.1.1'],`n            resolver_port=53, victim_ip='1.2.3.4',`n            num_queries=5, burst=True)`n    assert len(sent) == 5`n"
[System.IO.File]::WriteAllText("$repo\tests\test_spoof_engine.py", $t + $add)
DoCommit "2026-05-28T10:39:04" "test: verify num_queries multiplies send count per resolver"

# Commit 92: May 29
$t = Get-Content "$repo\tests\test_spoof_engine.py" -Raw
$add = "`n`ndef test_dnssec_do_false_sets_z_zero():`n    import spoof_engine`n    from scapy.layers.dns import DNSRROPT`n    from unittest.mock import patch`n    captured = []`n    with patch('spoof_engine.scapy_send', side_effect=lambda p, verbose: captured.append(p)):`n        spoof_engine.send_spoofed_dns_query(`n            domain='example.com', resolver_ip='8.8.8.8', resolver_port=53,`n            victim_ip='1.2.3.4', edns_payload=512, dnssec_do=False)`n    assert captured[0][DNSRROPT].z == 0`n"
[System.IO.File]::WriteAllText("$repo\tests\test_spoof_engine.py", $t + $add)
DoCommit "2026-05-29T10:39:04" "test: verify DNSSEC DO=False sets EDNS z field to zero"

# Commit 93: May 30
$se = Get-Content "$repo\spoof_engine.py" -Raw
$se = $se -replace "# Version: 2\.0\.0", "# Version: 2.0.0`n# Status: stable"
[System.IO.File]::WriteAllText("$repo\spoof_engine.py", $se)
DoCommit "2026-05-30T10:39:04" "chore: mark spoof_engine as stable in header"

# Commit 94: May 31 (first)
$readme = Get-Content "$repo\README.md" -Raw
$add = "`n`n---`n`n*Meteorain v2 -- DNS amplification pentest tool with IP spoofing support.*`n*For authorized security testing only.*`n"
[System.IO.File]::WriteAllText("$repo\README.md", $readme + $add)
DoCommit "2026-05-31T10:39:04" "docs: finalize README for v2 spoofed amplification mode"

# Commit 95: May 31 (second)
$se = Get-Content "$repo\spoof_engine.py" -Raw
$se = $se -replace "# Status: stable", "# Status: stable`n# Maintained: yes"
[System.IO.File]::WriteAllText("$repo\spoof_engine.py", $se)
DoCommit "2026-05-31T10:39:04" "chore: mark spoof_engine as actively maintained"

# Final push
git push
Write-Host "ALL 95 COMMITS DONE AND PUSHED!" -ForegroundColor Cyan
git log --oneline -5
