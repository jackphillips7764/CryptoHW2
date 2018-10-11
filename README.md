My implementation of the Needham–Schroeder is in python. The reason for the protocol is that Alice wants to talk to bob securely.
They do not have a session key to use together and need some way to create one. So Bob and alice can both register to a server and
set up key with the server. Then when Alice wants to talk to Bob she can send to the server a request that I want to talk to Bob.
Then the server can respond with a package, encrypted with their already created key, containing a session key, and encrypted package
to send to Bob. Then Alice can decrypt the packet and grab session key. Then will send bob the encrypted package inside. Bob can
decrypt and get the session key. Now they both have a key to use with each other. For my implementation I added a timestamp to the
messages sent from server so the messages to Bob could not be replayed. Each key message expires after an hour.

For the initial setup of the key we were told to use diffie hellman. I generated two prime numbers g = 7 and p = some large prime.
I used openssl to generate large prime for p. Then Alice and the Server generate some numbers and raise g to them and mod by p. Each
then sends that number to the other. They then both take that number and raise it to the private number they used in previous step and
mod by p. At the end they both end up with a number s that is the same. It is vulnerable to man in the middle, but not to someone
just listening in. I then used this s to generate a AES key to use for the rest of the communication. I used AES for my encryption
over my DES because our DES implementation key length is very short. I wanted this to be secure, but the DES algo could easily be
plugged in to this implementation.

For my implementation I have two clients Alice and Bob. Both Alice and Bob will register with the server and get a key to use.
This uses procedure described above. Then Alice will make a request to talk to Bob. The server will then make the packet for
Needham–Schroeder and send it to Alice. Alice then will decrypt and send Bob’s portion to him. They will then do a check with a
value to make sure that they both have key. Then Alice sends a message to show that all is working. All my requests are :
seperated with the type being first. With my talk request you give it a packet that is like this “talk:Alice:(encrypted data
with who you want to talk to)”. The last part is encrypted so people don’t know who you want to talk to.

To run my implementation you need to run the server.py file first then bob.py
and then finally alice.py. This is because when alice make request to talk to bob,
bob must be already registered and waiting for people to talk to him. You need to have pycrpto to run also.

Run like this in this order:
python2 server.py
python2 bob.py
python2 alice.py

