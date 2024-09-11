#!/usr/bin/env python3

import sys
import socket   

def server(port):
    serversock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversock.bind(('localhost', port))
    serversock.listen(5)

    while True:
        clientsock, addr = serversock.accept()
        while True:
            msglenbytes = clientsock.recv(2)
            msglen = int.from_bytes(msglenbytes, 'big')
            chunk = clientsock.recv(msglen)
            if chunk == b'':
                break
            sys.stdout.buffer.write(chunk)

        serversock.close()
        break

def client(port):
    clientsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_ip = sys.argv[1]

    file = sys.stdin.buffer.read()
    msglen = len(file)
    finalmsg = msglen.to_bytes(2, 'big')
    finalmsg += file
    finallen = len(finalmsg)

    totalsent = 0
    clientsock.connect((server_ip, port))
    while totalsent < finallen:
        sent = clientsock.send(finalmsg[totalsent:])
        totalsent = totalsent + sent
        print(totalsent)

    clientsock.close()

portstr = sys.argv[2]
port = int(portstr)
if sys.argv[1] == '-l':
    server(port)
else:
    client(port)
