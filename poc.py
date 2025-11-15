import socket
import threading
import argparse

def get_resolvers_from_file(file_path):
    with open(file_path, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def send_dns_query(domain_name, dns_server_address, dns_server_port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        identifier = (0x1337).to_bytes(2, 'big')
        flags = (0).to_bytes(2, 'big')
        qdcount = (1).to_bytes(2, 'big')
        qtype = (1).to_bytes(2, 'big')
        qclass = (1).to_bytes(2, 'big')
        labels = domain_name.split('.')
        qname = b''.join(len(l).to_bytes(1,'big')+l.encode() for l in labels) + b'\x00'
        query = identifier + flags + qdcount + b'\x00\x00\x00\x00\x00\x00' + qname + qtype + qclass
        s.sendto(query, (dns_server_address, dns_server_port))
        data, _ = s.recvfrom(1024)
        print(data.hex())
    finally:
        s.close()

def send_queries_through_resolvers(domain, resolvers, port):
    threads = []
    for r in resolvers:
        t = threading.Thread(target=send_dns_query, args=(domain, r, port))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument('-d','--domain', required=True)
    p.add_argument('-s','--server_address')
    p.add_argument('-f','--file')
    p.add_argument('-p','--port', type=int, default=53)
    args = p.parse_args()
    if args.file:
        resolvers = get_resolvers_from_file(args.file)
        send_queries_through_resolvers(args.domain, resolvers, args.port)
    if args.server_address:
        send_dns_query(args.domain, args.server_address, args.port)
