# server.py
import socket
import time

from RSA import RSA_encrypt
from elsig import signMessage
from gost import *

print("\nWelcome to Chat Room\n")
print("Initialising....\n")
time.sleep(1)

s = socket.socket()
host = socket.gethostname()
ip = socket.gethostbyname(host)
port = 1234
s.bind((host, port))
print(host, "(", ip, ")\n")
name = input(str("Enter your name: "))

s.listen(1)
print("\nWaiting for incoming connections...\n")
conn, addr = s.accept()
print("Received connection from ", addr[0], "(", addr[1], ")\n")

s_name = conn.recv(1024)
s_name = s_name.decode()
print(s_name, "has connected to the chat room\nEnter [e] to exit chat room\n")
conn.send(name.encode())

# receive client's n and public key
n = int(conn.recv(1024).decode())
public_key = int(conn.recv(1024).decode())

# GOST key
GOST_key = 0x1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff
# encrypted GOST key using RSA encryption with client's public key
encrypted_key = RSA_encrypt(GOST_key, public_key, n)

while True:
    message = input(str("Me : "))
    if message == "[e]":
        message = "Left chat room!"
        conn.send(message.encode())
        print("\n")
        break

    # text = fitted text to use GOST with # my_GOST = GOST object
    text, my_GOST = GOST_init(message,GOST_key)

    # encrypt message with GOST
    message = GOST_encrypt(text, my_GOST)
    encrypt_msg = " ".join(message)

    # send encrypted GOST key to client
    conn.send(str(encrypted_key).encode())

    # send GOST encrypted message to client
    conn.send(encrypt_msg.encode())

    # create and send signature to client
    signature = signMessage(encrypt_msg)
    conn.send(signature.encode())

    message = conn.recv(1024)
    message = message.decode()
    print(s_name, ":", message)
