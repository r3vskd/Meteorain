import socket
import threading
import time
import argparse

def display_banner():
    print("Usage: python poc.py -d domain.com -s 8.8.8.8 -p 53")

def get_resolvers_from_file(file_path):
    with open(file_path, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def send_dns_query(domain_name, dns_server_address, dns_server_port, verbose=False):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\ns.settimeout(1.0)
    try:
        identifier = (0x1337).to_bytes(2, 'big')
        flags = (0x0100).to_bytes(2, 'big')
        qdcount = (1).to_bytes(2, 'big')
        qtype = (1).to_bytes(2, 'big')
        qclass = (1).to_bytes(2, 'big')
        labels = domain_name.split('.')
        qname = b''.join(len(l).to_bytes(1,'big')+l.encode() for l in labels) + b'\x00'
        query = identifier + flags + qdcount + b'\x00\x00\x00\x00\x00\x00' + qname + qtype + qclass
        s.sendto(query, (dns_server_address, dns_server_port))
        data, _ = s.recvfrom(1024)
        if verbose:
            print(data.hex())
    finally:
        s.close()

def send_queries_through_resolvers(domain, resolvers, port, num_queries=1, interval=1.0, verbose=False):
    threads = []
    for r in resolvers:
        for _ in range(num_queries):
            t = threading.Thread(target=send_dns_query, args=(domain, r, port, verbose))
            threads.append(t)
            t.start()
            time.sleep(interval)
    for t in threads:
        t.join()

if __name__ == "__main__":
    p = argparse.ArgumentParser(description='DNS query sender')
    p.add_argument('-d','--domain', type=str)
    p.add_argument('-s','--server_address', type=str)
    p.add_argument('-f','--file', type=str)
    p.add_argument('-p','--port', type=int, default=53)
    p.add_argument('-q','--num_queries', type=int, default=1)
    p.add_argument('-i','--interval', type=float, default=1.0)
    p.add_argument('-v','--verbose', action='store_true')
    a = p.parse_args()
    if not a.domain or not a.port:
        display_banner()
    else:
        if a.file:
            rs = get_resolvers_from_file(a.file)
            send_queries_through_resolvers(a.domain, rs, a.port, a.num_queries, a.interval, a.verbose)
        if a.server_address:
            send_dns_query(a.domain, a.server_address, a.port, a.verbose)

