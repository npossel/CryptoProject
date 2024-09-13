#!/usr/bin/env python3

import sys
import socket
import select
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random.random import randint
from Crypto.Hash import SHA256

def proxy(sport, cport, g, p):
    hc = SHA256.new()
    hs = SHA256.new()
    data = 0
    proxysockC = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    proxysockC.bind(('localhost', cport))
    proxysockC.listen(5)
    clientsock, addr = proxysockC.accept()

    serversock.connect((sys.argv[3], sport))

    privkey = randint(0,p)
    pubkeyP = str(pow(g, privkey, p)).zfill(384)
    pubkeyP = pubkeyP.encode("utf-8")

    cw = 0
    cr = 0
    sw = 0
    sr = 0

    while True:
        read, write, error = select.select([serversock, clientsock], [serversock, clientsock], [])
        if clientsock in write and cw == 0:
            clientsock.send(pubkeyP)
            cw = 1

        if clientsock in read and cr == 0:
            pubkeyCbytes = clientsock.recv(384).decode("utf-8")

            pubkeyC = int(pubkeyCbytes)
            sharedpass = pow(pubkeyC, privkey, p)
            hexsharedpass = '%x' % sharedpass
            hexsharedpass = hexsharedpass.encode('utf-8')
            hc.update(hexsharedpass)
            keyC = hc.digest()[:32]
            cr = 1

        if serversock in write and sw == 0:
            serversock.send(pubkeyP)
            sw = 1

        if serversock in read and sr == 0:
            pubkeySbytes = serversock.recv(384).decode("utf-8")

            pubkeyS = int(pubkeySbytes)
            sharedpass = pow(pubkeyS, privkey, p)
            hexsharedpass = '%x' % sharedpass
            hexsharedpass = hexsharedpass.encode('utf-8')
            hs.update(hexsharedpass)
            keyS = hs.digest()[:32]
            sr = 1

        read, write, error = select.select([clientsock], [serversock], [])
        if clientsock in read and cr == 1:
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
                    cipher = AES.new(keyC, AES.MODE_GCM, nonce)
                    datapad = cipher.decrypt_and_verify(endata, tag)
                    data = unpad(datapad, 16)
                except:
                    print("Error: integrity check failed.", file=sys.stderr)

        if serversock in write and data != 0 and sw == 1:
            cipher = AES.new(keyS, AES.MODE_GCM)
            ciphertext, tag = cipher.encrypt_and_digest(pad(data, 16))
            foo = cipher.nonce+tag+ciphertext

            msglen = len(foo)
            finalmsg = msglen.to_bytes(2, 'big')
            finalmsg += foo
            finallen = len(finalmsg)
            
            totalsent = 0
            while totalsent < finallen:
                sent = serversock.send(finalmsg[totalsent:])
                totalsent = totalsent + sent
            data = 0
            break

    proxysockC.close()
    clientsock.close()
    serversock.close()

g=2
p=0x00cc81ea8157352a9e9a318aac4e33ffba80fc8da3373fb44895109e4c3ff6cedcc55c02228fccbd551a504feb4346d2aef47053311ceaba95f6c540b967b9409e9f0502e598cfc71327c5a455e2e807bede1e0b7d23fbea054b951ca964eaecae7ba842ba1fc6818c453bf19eb9c5c86e723e69a210d4b72561cab97b3fb3060b
cportstr = sys.argv[2]
sportstr = sys.argv[4]
cport = int(cportstr)
sport = int(sportstr)
proxy(sport, cport, g, p)
