from Crypto.Util.number import *
from Crypto import Random
import Crypto

import libnum
import sys
from random import randint
import hashlib

bits = 60
msg = "Hello"

if len(sys.argv) > 1:
    msg = str(sys.argv[1])
if len(sys.argv) > 2:
    bits = int(sys.argv[2])

p = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)  # large prime p
g = 2  # primitive root

s = randint(0, p - 1)  # private key
v = pow(g, s, p)  # public key: v=g^s mod p
# e is a random integer with a conditions of 1 <= e <= (p-1) and gcd(e,p-1)=1
e = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
e_1 = (libnum.invmod(e, p - 1))  # the inverse of e mod (p-1)

D = int.from_bytes(hashlib.sha256(msg.encode()).digest(), byteorder='big')  # hashed message

# signatures:
S_1 = pow(g, e, p)  # temporary key (r)
S_2 = ((D - s * S_1) * e_1) % (p - 1)  # value of S2

# verification:
v_1 = (pow(v, S_1, p) * pow(S_1, S_2, p)) % p
v_2 = pow(g, D, p)

# v_1 and v_2 should match

print("Message: %s " % msg)
print("g: %s" % g)
print("p: %s" % p)
print("\nv: %s" % v)
print("e: %s" % e)
print("\ns: %s" % s)

print("\nS_1= %s" % S_1)
print("S_2=%s" % S_2)
print("\nV_1=%s" % v_1)
print("v_2=%s" % v_2)
