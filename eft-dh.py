#!/usr/bin/env python3

import sys
import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random.random import randint
from Crypto.Hash import SHA256

def server(port, g, p):
    h = SHA256.new()
    serversock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversock.bind(('localhost', port))
    serversock.listen(5)

    while True:
        clientsock, addr = serversock.accept()

        privkey = randint(0,p)
        pubkeyS = str(pow(g, privkey, p)).zfill(384)
        pubkeyS = pubkeyS.encode("utf-8")

        clientsock.send(pubkeyS)
        pubkeyCbytes = clientsock.recv(384).decode("utf-8")

        pubkeyC = int(pubkeyCbytes)
        sharedpass = pow(pubkeyC, privkey, p)
        hexsharedpass = '%x' % sharedpass
        hexsharedpass = hexsharedpass.encode('utf-8')
        h.update(hexsharedpass)
        key = h.digest()[:32]

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
                print("Error: integrity check failed.", file=sys.stderr)

        serversock.close()
        clientsock.close()
        break

def client(port, g, p):
    h = SHA256.new()
    clientsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_ip = sys.argv[1]
    clientsock.connect((server_ip, port))

    privkey = randint(0,p)
    pubkeyC = str(pow(g, privkey, p)).zfill(384)
    pubkeyC = pubkeyC.encode("utf-8")

    clientsock.send(pubkeyC)
    pubkeySbytes = clientsock.recv(384).decode("utf-8")

    pubkeyS = int(pubkeySbytes)
    sharedpass = pow(pubkeyS, privkey, p)
    hexsharedpass = '%x' % sharedpass
    hexsharedpass = hexsharedpass.encode('utf-8')
    h.update(hexsharedpass)
    key = h.digest()[:32]

    file = sys.stdin.buffer.read()
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(pad(file, 16))
    foo = cipher.nonce+tag+ciphertext

    msglen = len(foo)
    finalmsg = msglen.to_bytes(2, 'big')
    finalmsg += foo
    finallen = len(finalmsg)

    totalsent = 0
    while totalsent < finallen:
        sent = clientsock.send(finalmsg[totalsent:])
        totalsent = totalsent + sent

    clientsock.close()

g=2
p=0x00cc81ea8157352a9e9a318aac4e33ffba80fc8da3373fb44895109e4c3ff6cedcc55c02228fccbd551a504feb4346d2aef47053311ceaba95f6c540b967b9409e9f0502e598cfc71327c5a455e2e807bede1e0b7d23fbea054b951ca964eaecae7ba842ba1fc6818c453bf19eb9c5c86e723e69a210d4b72561cab97b3fb3060b
portstr = sys.argv[2]
port = int(portstr)
if sys.argv[1] == '-l':
    server(port, g, p)
else:
    client(port, g, p)
