from Crypto.Util.number import *
from Crypto import Random
import Crypto

import libnum
import sys
from random import randint
import hashlib

bits = 60
g = 2  # primitive root

def signMessage(message):
    msg = message

    p = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)  # large prime p
    privateKey = randint(0, p - 1)  # private key s
    publicKey = pow(g, privateKey, p)  # public key v: v=g^s mod p

    # e is a random integer with a conditions of 1 <= e <= (p-1) and gcd(e,p-1)=1
    e = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
    e_1 = (libnum.invmod(e, p - 1))  # the inverse of e mod (p-1)

    hashedMessage = int.from_bytes(hashlib.sha256(msg.encode()).digest(), byteorder='big')  # hashed message

    # signatures:
    S_1 = pow(g, e, p)  # temporary key (r)
    S_2 = ((hashedMessage - privateKey * S_1) * e_1) % (p - 1)  # signature
    return ""+str(S_2)+" "+str(S_1)+" "+str(publicKey)+" "+str(hashedMessage)+" "+str(p)


def verifyMessage(signatureArray):
    S_2 = int(signatureArray[0])
    S_1 = int(signatureArray[1])
    publicKey = int(signatureArray[2])
    hashedMessage = int(signatureArray[3])
    p = int(signatureArray[4])

    # verification:
    v_1 = (pow(publicKey, S_1, p) * pow(S_1, S_2, p)) % p
    v_2 = pow(g, hashedMessage, p)

    # v_1 and v_2 should match
    if v_1 == v_2: return True
    else: return False
