from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Random import get_random_bytes
import Crypto
import libnum

bits = 128  # number of bits to match key length


def get_keys():
    p = Crypto.Util.number.getPrime(bits, randfunc=get_random_bytes)
    q = Crypto.Util.number.getPrime(bits, randfunc=get_random_bytes)

    n = p * q
    PHI = (p - 1) * (q - 1)

    e = 65537
    d = libnum.invmod(e, PHI)

    return d, e, n


def RSA_encrypt(GOST_key, public_key, n):
    return pow(GOST_key, public_key, n)


def RSA_decrypt(encrypted_key_client, private_key, n):
    return pow(int(encrypted_key_client), private_key, n)
