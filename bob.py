import socket
from Crypto.Util.number import *
from Crypto.Cipher import AES
import os
from hashlib import *
import time

g = 7
p = 19480578657941212121091284695189676437071357476859942928493352030954357750973459010931221555560793388848623660231094721811393236830243532333739739079088525690332386584873693579490017752146859491807277363233877868528572632116898235131293368980084424890653241867746064752309680618736037871308324374286552764968522984830427456280213923973136007654762139411354162697234500485649779688587754121994410542830934918361813240451352197621878278286112403658233459961435352678740261752509427756194102302159850509978731020633173704146063527894095091912232986874258884131708438598011495844326656774222116794994136054412537291349747

#commented in alice.py :>
def pad(s):
    return s + (32 - len(s) % 32) * chr(32 - len(s) % 32)

def unpad(s):
    return s[:-ord(s[len(s)-1:])]

def encrypt(key, msg):
    iv = "\x00"*AES.block_size
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher = cipher.encrypt(pad(msg))
    return cipher.encode('base64')
def decrypt(key, msg):
    iv = "\x00"*AES.block_size
    enc = msg.decode('base64')
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc))

def register(conn, name):
    conn.send('register')
    b = bytes_to_long(os.urandom(1024))
    B = pow(g, b, p)
    A = int(conn.recv(2048))
    conn.send(str(B))
    s = pow(A, b, p)
    print s
    key = sha256(long_to_bytes(s)).digest()
    conn.send(encrypt(key, name))
    response = decrypt(key, conn.recv(2048))
    if response == 'Name Taken\n':
        print "diffrent name needed"
        print 'failed to register'
        return -1
    return key

def nsProto(conn, key, name, talk_to):
    Na = os.urandom(100).encode('hex')
    request = 'talk:' + name
    request += ':'
    request += encrypt(key, talk_to + ':' + Na)
    print request
    conn.send(request)
    packet = conn.recv(10000)
    packet = decrypt(key, packet).split(':')
    if Na != packet[0]:
        print "FAILURE"
        sys.exit()
    return packet
    conn.close()

def recvdecode(packet):
    packet = decrypt(key, packet)
    packet = packet.split(':')
    session_key = packet[0]
    timestamp = float(packet[2])
    #check timstamp is less then hour ago
    print abs(timestamp - time.time())
    if abs(timestamp - time.time()) > 216000:
        print "Timestamp too old"
        sys.exit(1)
    name = packet[1]
    return (session_key.decode('base64'), name)

conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', 1234)
conn.connect(server_address)

name = 'Bob'
key = register(conn, name)

#now listen for comunication
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(('0.0.0.0', 1337))

server.listen(4)
(conn, (ip, port)) = server.accept()

#alice connected
packet = recvdecode(conn.recv(4096))

#get sission_key from packet
(session_key, name) =  packet

nB = bytes_to_long(os.urandom(100))

conn.send(encrypt(session_key, str(nB)))
print nB
#make sure that we got back what we send minus 1
#comunication was set up
test = int(decrypt(session_key, conn.recv(1024)))
if test == nB -1:
    print "Everything works"
else:
    print 'FAIL'

print 'MSG RECVED:: ' + decrypt(session_key, conn.recv(1024))

server.close()
