import socket
import threading
import time
import os
from Crypto.Util.number import *
from Crypto.Cipher import AES
from hashlib import *

#Ip and port
IP = '0.0.0.0'
PORT = 1234

key_base = {}
mutex = threading.Lock()

#diffie helmen stuff
g = 7
p = 19480578657941212121091284695189676437071357476859942928493352030954357750973459010931221555560793388848623660231094721811393236830243532333739739079088525690332386584873693579490017752146859491807277363233877868528572632116898235131293368980084424890653241867746064752309680618736037871308324374286552764968522984830427456280213923973136007654762139411354162697234500485649779688587754121994410542830934918361813240451352197621878278286112403658233459961435352678740261752509427756194102302159850509978731020633173704146063527894095091912232986874258884131708438598011495844326656774222116794994136054412537291349747

#pad AES
def pad(s):
    return s + (32 - len(s) % 32) * chr(32 - len(s) % 32)

#unpad AES block
def unpad(s):
    return s[:-ord(s[len(s)-1:])]

#encrypt with AES a msg
def encrypt(key, msg):
    iv = "\x00"*AES.block_size
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher = cipher.encrypt(pad(msg))
    return cipher.encode('base64')

#decrypt with AES
def decrypt(key, msg):
    iv = "\x00"*AES.block_size
    enc = msg.decode('base64')
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc))

#build packet for the reueqst to talk to people
def build_packet(conn, keya, keyb, na, name, res):
    timestamp = str(time.time())
    keyab = sha256(os.urandom(1024)).digest().encode('base64')
    packet = na + ':'
    packet += keyab + ':'
    packet += res + ':'
    #sub packet with key ab for B to use encrypted witg key_b
    #this is decrypted by b and then both have same session key
    packet += encrypt(keyb, keyab + ':' +  name + ':' + timestamp)
    print packet
    packet = encrypt(keya, packet)
    conn.send(packet)

#class for talking to client thread
class ClientThread(threading.Thread):
    def __init__(self, conn):
        threading.Thread.__init__(self)
        self.conn = conn
    #run comunication with client
    def run(self):
        while True:
            #establish Diffyhelman
            try:
                msg = self.conn.recv(4096)
                print 'msgrecv'
            except socket.error, e:
                break
            if len(msg) == 0:
                break
            #register with key server
            if 'register' in msg:
                request = msg.split(':')
                print 'register'
                #make random a for diffie helman
                a = bytes_to_long(os.urandom(1024))
                A = pow(g, a, p)
                self.conn.send(str(A))
                #get B and use it to calc secrete
                B = int(self.conn.recv(2048))
                s = pow(B, a, p)
                print s
                #use as s to get an AES key to use
                #for comunication from here on out
                key = sha256(long_to_bytes(s)).digest()
                name = decrypt(key, self.conn.recv(2048))
                mutex.acquire()
                if name in key_base:
                    self.conn.send(encrypt(key, "Name Taken\n"))
                else:
                    key_base[name] = key
                    self.conn.send(encrypt(key, "Sucsess\n"))
                mutex.release()
            #talk is command to talk to another server
            if 'talk' in msg:
                #request split with :
                request = msg.split(':')
                if len(request) < 3: self.conn.close(); return;
                name = request[1]
                mutex.acquire()
                #use name to get key from base
                if name not in key_base:
                    self.conn.send("Register First\n")
                    self.conn.close()
                    mutex.release()
                    return
                #get the requesting user from packet
                key = key_base[name]
                r = decrypt(key, request[2])
                r = r.split(':', 1)
                if len(r) < 2: self.conn.close(); mutex.release(); return;
                resipient = r[0]
                Na = r[1]
                print len(Na)
                if resipient not in key_base:
                    self.conn.send(encrypt(key, 'Uknown recipient'))
                    self.conn.close()
                    mutex.release()
                    return
                keyB = key_base[resipient]
                mutex.release()
                #create first packet to send to client for key server
                #A to talk to B
                build_packet(self.conn, key, keyB, Na, name, resipient)
        print "closed"
        self.conn.close()

#make server for clients to connect to
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((IP, PORT))


server.listen(4)
while True:
    (conn, (ip, port)) = server.accept()
    thread = ClientThread(conn)
    #on new connection start up thread
    thread.start()

server.close()



