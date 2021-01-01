#!/usr/bin/env python

sbox = (
    (4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3),
    (14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9),
    (5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11),
    (7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3),
    (6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2),
    (4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14),
    (13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12),
    (1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12),
)


def _bit_length(x):
    assert x >= 0
    return len(bin(x)) - 2


def f_function(var, key):
    assert _bit_length(var) <= 32
    assert _bit_length(key) <= 32

    # (var + subkey)mod 2^32
    temp = (var + key) % (1 << 32)

    # sbox[row = round][column = decimal value of the 4bits]
    output = 0
    for i in range(8):
        output |= ((sbox[i][(temp >> (4 * i)) & 0b1111]) << (4 * i))

    # shift left 11
    output = ((output >> (32 - 11)) | (output << 11)) & 0xFFFFFFFF

    return output


def round_encryption(input_left, input_right, round_key):
    output_left = input_right
    output_right = input_left ^ f_function(input_right, round_key)

    return output_left, output_right


def round_decryption(input_left, input_right, round_key):
    output_right = input_left
    output_left = input_right ^ f_function(input_left, round_key)

    return output_left, output_right


class GOST:
    def __init__(self):
        self.master_key = [None] * 8

    def set_key(self, master_key):
        assert _bit_length(master_key) <= 256
        # master_key = [K0, K1, K2, K3, K4, K5, K6, K7]   32bits each subkey
        for i in range(8):
            self.master_key[i] = (master_key >> (32 * i)) & 0xFFFFFFFF
        # print 'master_key', [hex(i) for i in self.master_key]

    def encrypt(self, plaintext):
        assert _bit_length(plaintext) <= 64
        text_left = plaintext >> 32
        text_right = plaintext & 0xFFFFFFFF
        # print 'text', hex(text_left), hex(text_right)

        # K0, K1, K2, K3, K4, K5, K6, K7, K0, K1, K2, K3, K4, K5, K6, K7, K0, K1, K2, K3, K4, K5, K6, K7
        for i in range(24):
            text_left, text_right = round_encryption(
                text_left, text_right, self.master_key[i % 8])

        # K7, K6, K5, K4, K3, K2, K1, K0
        for i in range(8):
            text_left, text_right = round_encryption(
                text_left, text_right, self.master_key[7 - i])

        return (text_left << 32) | text_right

    def decrypt(self, ciphertext):
        assert _bit_length(ciphertext) <= 64
        text_left = ciphertext >> 32
        text_right = ciphertext & 0xFFFFFFFF

        # K0, K1, K2, K3, K4, K5, K6, K7
        for i in range(8):
            text_left, text_right = round_decryption(
                text_left, text_right, self.master_key[i])

        # K7, K6, K5, K4, K3, K2, K1, K0, K7, K6, K5, K4, K3, K2, K1, K0, K7, K6, K5, K4, K3, K2, K1, K0
        for i in range(24):
            text_left, text_right = round_decryption(
                text_left, text_right, self.master_key[(7 - i) % 8])

        return (text_left << 32) | text_right


def GOST_init(message, key):
    # key = 0x1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff

    my_GOST = GOST()
    my_GOST.set_key(key)

    tmp = message.upper()
    lst = tmp.split(' ')
    return lst, my_GOST


def GOST_encrypt(lst, my_GOST):
    num = 1000
    encryptionList = []

    # manipulate user text so it could be encrypted
    for t in lst:
        numList = [ord(c) for c in t]
        text = int(''.join(map(str, numList)))

        # print("mekori")
        # print(text)

        # print("encryption")
        for i in range(num):
            text = my_GOST.encrypt(text)
        # print(text)
        encryptionList.append(str(text))
    return encryptionList


def GOST_decrypt(lst, key):
    # key = 0x1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff
    my_GOST = GOST()
    my_GOST.set_key(key)


    num = 1000
    decryptionList = []
    lst = lst.split(' ')
    for text in lst:
        for i in range(num):
            text = my_GOST.decrypt(int(text))

        text = str(text)  # convert from int to str to use len()
        out = [(text[i:i + 2]) for i in range(0, len(text), 2)]  # split into list 2 digits per cell
        # print(out)  # ['12','34','56']

        word = ""
        for o in out:
            o = int(o)  # build word from int
            word += chr(o)  # build word + convert ascii code to char
        # print(word)
        decryptionList.append(word)

    decryptionText = " ".join(decryptionList).lower()  # join all the words in list
    return decryptionText
