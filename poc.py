import socket
import threading
import time
import argparse

QTYPE_MAP = {
    'A': 1,
    'AAAA': 28,
    'ANY': 255,
    'DNSKEY': 48,
    'DS': 43,
    'TXT': 16,
    'NS': 2,
    'CNAME': 5,
    'SOA': 6,
    'PTR': 12,
    'MX': 15,
    'SRV': 33,
    'NAPTR': 35,
    'CAA': 257,
}

def _print_dns_header(data):
    if len(data) < 12:
        return
    ident = int.from_bytes(data[0:2], 'big')
    flags = int.from_bytes(data[2:4], 'big')
    qd = int.from_bytes(data[4:6], 'big')
    an = int.from_bytes(data[6:8], 'big')
    ns = int.from_bytes(data[8:10], 'big')
    ar = int.from_bytes(data[10:12], 'big')
    qr = (flags >> 15) & 1
    opcode = (flags >> 11) & 0xF
    aa = (flags >> 10) & 1
    tc = (flags >> 9) & 1
    rd = (flags >> 8) & 1
    ra = (flags >> 7) & 1
    rcode = flags & 0xF
    names = {
        0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 4: 'NOTIMP', 5: 'REFUSED',
        6: 'YXDOMAIN', 7: 'YXRRSET', 8: 'NXRRSET', 9: 'NOTAUTH', 10: 'NOTZONE'
    }
    n = names.get(rcode, str(rcode))
    print(f"ID={ident} QR={qr} OPCODE={opcode} AA={aa} TC={tc} RD={rd} RA={ra} RCODE={n} QD={qd} AN={an} NS={ns} AR={ar}")

def _select_af(address, af_hint):
    if af_hint == '6':
        return socket.AF_INET6
    if af_hint == '4':
        return socket.AF_INET
    return socket.AF_INET6 if (':' in address) else socket.AF_INET

def get_resolvers_from_file(file_path):
    with open(file_path, 'r') as file:
        items = []
        for line in file.readlines():
            t = line.strip()
            if not t or t.startswith('#'):
                continue
            items.append(t)
        return items

def get_address_port():
    address = input("Enter server address: ")
    port = int(input("Enter server port: "))
    return address, port

def send_dns_query(domain_name, dns_server_address, dns_server_port, timeout, bufsize, verbose, qtype_name='A', edns_payload=0, dnssec_do=False, measure=False, rd=True, src_port=0, tcp_on_trunc=False, retries=0, latency=False, af='auto', edns_nsid=False, qclass=1, txid=0x1337, src_addr=None, raw_hex=False, print_query=False):
    client_socket = socket.socket(_select_af(dns_server_address, af), socket.SOCK_DGRAM)
    server_address = (dns_server_address, dns_server_port)

    try:
        client_socket.settimeout(timeout)
        identifier = int(txid).to_bytes(2, byteorder='big', signed=False)
        flags = (0x0100 if rd else 0).to_bytes(2, byteorder='big')
        qdcount = (1).to_bytes(2, byteorder='big')
        qtype_value = QTYPE_MAP.get(qtype_name.upper(), 1)
        qtype = (qtype_value).to_bytes(2, byteorder='big')
        qclass_bytes = int(qclass).to_bytes(2, byteorder='big', signed=False)

        dn = domain_name.strip('.').lower()
        labels = dn.split('.')
        qname = b''.join(len(label).to_bytes(1, byteorder='big') + label.encode() for label in labels) + b'\x00'

        ancount = (0).to_bytes(2, byteorder='big')
        nscount = (0).to_bytes(2, byteorder='big')
        arcount = (1).to_bytes(2, byteorder='big') if edns_payload > 0 else (0).to_bytes(2, byteorder='big')
        dns_query = identifier + flags + qdcount + ancount + nscount + arcount + qname + qtype + qclass_bytes

        if edns_payload > 0:
            opt_name = b'\x00'
            opt_type = (41).to_bytes(2, byteorder='big')
            opt_udp_payload = (edns_payload).to_bytes(2, byteorder='big')
            ext_rcode = (0).to_bytes(1, byteorder='big')
            version = (0).to_bytes(1, byteorder='big')
            flags_do = (0x8000 if dnssec_do else 0).to_bytes(2, byteorder='big')
            rdata = b''
            if edns_nsid:
                rdata += (3).to_bytes(2, 'big') + (0).to_bytes(2, 'big')
            rdata_len = (len(rdata)).to_bytes(2, 'big')
            opt_record = opt_name + opt_type + opt_udp_payload + ext_rcode + version + flags_do + rdata_len + rdata
            dns_query += opt_record

        if verbose:
            print(f"Sending DNS query for {domain_name} to {dns_server_address}:{dns_server_port}")
            if print_query:
                print(dns_query.hex())
            if measure:
                print(f"Query size: {len(dns_query)} bytes")

        if src_port and src_port > 0:
            try:
                bind_addr = src_addr if src_addr else ('::' if _select_af(dns_server_address, af) == socket.AF_INET6 else '0.0.0.0')
                client_socket.bind((bind_addr, src_port))
            except Exception:
                pass
        attempt = 0
        while True:
            start_time = time.perf_counter() if latency else None
            client_socket.sendto(dns_query, server_address)
            try:
                data, _ = client_socket.recvfrom(bufsize)
                if latency and start_time is not None:
                    elapsed_ms = (time.perf_counter() - start_time) * 1000.0
                    print(f"Latency: {elapsed_ms:.2f} ms")
                if verbose:
                    print(f"Received DNS Response for {domain_name}:")
                    _print_dns_header(data)
                    print(data.hex())
                    if measure:
                        print(f"Response size: {len(data)} bytes, ratio: {round(len(data)/len(dns_query), 2)}x")
                if tcp_on_trunc and len(data) >= 4:
                    flags_int = int.from_bytes(data[2:4], 'big')
                    if (flags_int & 0x0200) != 0:
                        try:
                            if verbose:
                                print("Truncated UDP response, retrying via TCP")
                            send_dns_query_tcp(domain_name, dns_server_address, dns_server_port, timeout, bufsize, verbose, qtype_name, edns_payload, dnssec_do, measure, rd)
                        except Exception:
                            pass
                if raw_hex and not verbose:
                    print(data.hex())
                break
            except socket.timeout:
                attempt += 1
                if verbose:
                    print(f"Timeout waiting for DNS response for {domain_name}")
                if attempt > retries:
                    break
                time.sleep(0.05)

    finally:
        client_socket.close()

def send_queries_through_resolvers(domain, resolvers, server_port, num_queries, interval, timeout, bufsize, verbose, qtype_name='A', edns_payload=0, dnssec_do=False, measure=False, rd=True, src_port=0, tcp_on_trunc=False, retries=0, latency=False, af='auto', edns_nsid=False, qclass=1, txid=0x1337, src_addr=None, raw_hex=False):
    threads = []
    for resolver in resolvers:
        for _ in range(num_queries):
            thread = threading.Thread(target=send_dns_query, args=(domain, resolver, server_port, timeout, bufsize, verbose, qtype_name, edns_payload, dnssec_do, measure, rd, src_port, tcp_on_trunc, retries, latency, af, edns_nsid, qclass, txid, src_addr, raw_hex))
            threads.append(thread)
            thread.start()
            time.sleep(interval)

    for thread in threads:
        thread.join()

def display_banner():
    print('''
█▀▄▀█ ▄███▄     ▄▄▄▄▀ ▄███▄   ████▄ █▄▄▄▄ ██   ▄█    ▄   
█ █ █ █▀   ▀ ▀▀▀ █    █▀   ▀  █   █ █  ▄▀ █ █  ██     █  
█ ▄ █ ██▄▄       █    ██▄▄    █   █ █▀▀▌  █▄▄█ ██ ██   █ 
█   █ █▄   ▄▀   █     █▄   ▄▀ ▀████ █  █  █  █ ▐█ █ █  █ 
   █  ▀███▀    ▀      ▀███▀           █      █  ▐ █  █ █ 
  ▀                                  ▀      █     █   ██ 
                                           ▀  Author: r3vskd
                                              Warning: It was created for educational purposes. Please don't misuse it for illegal activities.         
''')
    print("Usage:")
    print(" $python ./poc.py -f resolvers.txt -d domain.com -s xxx.xxx.xxx.xxx -p 53 -q 4 -i 1\n")
    print("Options:")
    print("  -f or --file             DNS Resolvers txt file")
    print("  -d or --domain           Set the domain name to query")
    print("  -s or --server_address   Set the dns server address")
    print("  -p or --port             Set the server port")
    print("  -q or --num_queries      Set the number of queries to send (Default: 1)")
    print("  -i or --interval         Set the interval between queries in seconds (Default: 1 second)")
    print("  -v or --verbose          Enable verbose mode (optional)\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='DNS query sender')
    parser.add_argument('-d', '--domain', type=str, help='Domain name to query')
    parser.add_argument('-f', '--file', type=str, help='Path to the file containging DNS resolver addresses')
    parser.add_argument('-s', '--server_address', type=str, help='DNS server address')
    parser.add_argument('-p', '--port', type=int, help='DNS server port')
    parser.add_argument('-q', '--num_queries', type=int, default=1, help='Number of queries to send')
    parser.add_argument('-i', '--interval', type=float, default=1.0, help='Interval between queries in seconds')
    parser.add_argument('--timeout', type=float, default=2.0, help='Socket timeout in seconds')
    parser.add_argument('--bufsize', type=int, default=4096, help='UDP receive buffer size')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose mode')
    parser.add_argument('--qtype', type=str, default='A', help='DNS query type')
    parser.add_argument('--edns_payload', type=int, default=1232, help='EDNS UDP payload size')
    parser.add_argument('--dnssec_do', action='store_true', help='Enable DNSSEC DO bit')
    parser.add_argument('--measure', action='store_true', help='Show query/response sizes and ratio')
    parser.add_argument('--no_rd', action='store_true', help='Disable RD flag')
    parser.add_argument('--src_port', type=int, default=0, help='Bind local source port')
    parser.add_argument('--tcp', action='store_true', help='Use TCP transport')
    parser.add_argument('--tcp_on_trunc', action='store_true', help='Fallback to TCP on truncation')
    parser.add_argument('--retry', type=int, default=0, help='Retry count on timeout')
    parser.add_argument('--latency', action='store_true', help='Print DNS latency')
    parser.add_argument('--tcp_bufsize', type=int, default=None, help='TCP receive buffer size')
    parser.add_argument('--edns_nsid', action='store_true', help='Request NSID via EDNS')
    parser.add_argument('--qclass', type=int, default=1, help='Query class (default IN=1)')
    parser.add_argument('--id', type=int, default=0x1337, help='Transaction ID')
    parser.add_argument('--src_addr', type=str, default=None, help='Bind local source address')
    parser.add_argument('--af', type=str, default='auto', choices=['auto','4','6'], help='Address family (auto/4/6)')
    parser.add_argument('--hex', action='store_true', help='Print raw hex of responses')
    parser.add_argument('--tcp_nodelay', action='store_true', help='Disable Nagle for TCP')

    args = parser.parse_args()

    if not args.domain or not args.port:
        display_banner()
    else:
        if args.file:
            resolvers = get_resolvers_from_file(args.file)
            send_queries_through_resolvers(args.domain, resolvers, args.port, args.num_queries, args.interval, args.timeout, args.bufsize, args.verbose, args.qtype, args.edns_payload, args.dnssec_do, args.measure, not args.no_rd, args.src_port, args.tcp_on_trunc, args.retry, args.latency, args.af, args.edns_nsid, args.qclass, args.id, args.src_addr, args.hex)
        if args.server_address:
            if args.tcp:
                send_dns_query_tcp(args.domain, args.server_address, args.port, args.timeout, args.bufsize, args.verbose, args.qtype, args.edns_payload, args.dnssec_do, args.measure, not args.no_rd, args.af, args.tcp_bufsize, args.edns_nsid, args.qclass, args.id, args.hex, args.tcp_nodelay)
            else:
                send_dns_query(args.domain, args.server_address, args.port, args.timeout, args.bufsize, args.verbose, args.qtype, args.edns_payload, args.dnssec_do, args.measure, not args.no_rd, args.src_port, args.tcp_on_trunc, args.retry, args.latency, args.af, args.edns_nsid, args.qclass, args.id, args.src_addr, args.hex)
        if not args.file and not args.server_address:
            print("Please provide a file containing DNS resolver addresses using -f/--file or specify the server using -s/--server_address.")
def send_dns_query_tcp(domain_name, dns_server_address, dns_server_port, timeout, bufsize, verbose, qtype_name='A', edns_payload=0, dnssec_do=False, measure=False, rd=True, af='auto', tcp_bufsize=None, edns_nsid=False, qclass=1, txid=0x1337, raw_hex=False, tcp_nodelay=False, print_query=False):
    s = socket.socket(_select_af(dns_server_address, af), socket.SOCK_STREAM)
    s.settimeout(timeout)
    if tcp_nodelay:
        try:
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            pass
    identifier = int(txid).to_bytes(2, 'big', signed=False)
    flags = (0x0100 if rd else 0).to_bytes(2, 'big')
    qdcount = (1).to_bytes(2, 'big')
    qtype_value = QTYPE_MAP.get(qtype_name.upper(), 1)
    qtype = (qtype_value).to_bytes(2, 'big')
    qclass_bytes = int(qclass).to_bytes(2, 'big', signed=False)
    dn = domain_name.strip('.').lower()
    labels = dn.split('.')
    qname = b''.join(len(label).to_bytes(1, 'big') + label.encode() for label in labels) + b'\x00'
    ancount = (0).to_bytes(2, 'big')
    nscount = (0).to_bytes(2, 'big')
    arcount = (1).to_bytes(2, 'big') if edns_payload > 0 else (0).to_bytes(2, 'big')
    query = identifier + flags + qdcount + ancount + nscount + arcount + qname + qtype + qclass_bytes
    if edns_payload > 0:
        opt_name = b'\x00'
        opt_type = (41).to_bytes(2, 'big')
        opt_udp_payload = (edns_payload).to_bytes(2, 'big')
        ext_rcode = (0).to_bytes(1, 'big')
        version = (0).to_bytes(1, 'big')
        flags_do = (0x8000 if dnssec_do else 0).to_bytes(2, 'big')
        rdata = b''
        if edns_nsid:
            rdata += (3).to_bytes(2, 'big') + (0).to_bytes(2, 'big')
        rdata_len = (len(rdata)).to_bytes(2, 'big')
        opt_record = opt_name + opt_type + opt_udp_payload + ext_rcode + version + flags_do + rdata_len + rdata
        query += opt_record
    length = len(query).to_bytes(2, 'big')
    s.connect((dns_server_address, dns_server_port))
    if verbose and print_query:
        print(query.hex())
    s.sendall(length + query)
    try:
        data = s.recv(tcp_bufsize or bufsize)
        if verbose:
            _print_dns_header(data)
            print(data.hex())
        elif raw_hex:
            print(data.hex())
        if measure:
            print(f"Query size: {len(query)} bytes")
            print(f"Response size: {len(data)} bytes")
            if len(query) > 0:
                print(f"Ratio: {round(len(data)/len(query), 2)}x")
    finally:
        s.close()
