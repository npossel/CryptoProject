#!/usr/bin/env python3

import sys
import socket
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def server(port, password):
    serversock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversock.bind(('localhost', port))
    serversock.listen(5)

    while True:
        clientsock, addr = serversock.accept()
        salt = clientsock.recv(16)
        key = PBKDF2(password, salt, 32)

        while True:
            msglenbytes = clientsock.recv(2)
            msglen = int.from_bytes(msglenbytes, 'big')
            nonce = clientsock.recv(16)
            tag = clientsock.recv(16)
            datalen = msglen-32
            if datalen < 0:
                break
            endata = clientsock.recv(datalen)
            if endata == b'':
                break
            
            try: 
                cipher = AES.new(key, AES.MODE_GCM, nonce)
                datapad = cipher.decrypt_and_verify(endata, tag)
                data = unpad(datapad, 16)
                sys.stdout.buffer.write(data)
            except:
                print("Error: integrity check failed.", file=sys. stderr)

        serversock.close()
        break

def client(port, password):
    clientsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_ip = sys.argv[3]

    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, 32)
    file = sys.stdin.buffer.read()
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(pad(file, 16))
    foo = cipher.nonce+tag+ciphertext

    msglen = len(foo)
    finalmsg = msglen.to_bytes(2, 'big')
    finalmsg += foo
    finallen = len(finalmsg)

    totalsent = 0
    clientsock.connect((server_ip, port))

    clientsock.send(salt)
    while totalsent < finallen:
        sent = clientsock.send(finalmsg[totalsent:])
        totalsent = totalsent + sent

    clientsock.close()

password = sys.argv[2]
portstr = sys.argv[4]
port = int(portstr)
if sys.argv[3] == '-l':
    server(port, password)
else:
    client(port, password)
