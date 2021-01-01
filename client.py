# client.py
import socket
import time

from RSA import get_keys, RSA_decrypt
from elsig import verifyMessage
from gost import *

print("\nWelcome to Chat Room\n")
print("Initialising....\n")
time.sleep(1)

s = socket.socket()
shost = socket.gethostname()
ip = socket.gethostbyname(shost)
print(shost, "(", ip, ")\n")
host = input(str("Enter server address: "))
name = input(str("\nEnter your name: "))
port = 1234
print("\nTrying to connect to ", host, "(", port, ")\n")
time.sleep(1)
s.connect((host, port))
print("Connected...\n")

s.send(name.encode())
s_name = s.recv(1024)
s_name = s_name.decode()
print(s_name, "has joined the chat room\nEnter [e] to exit chat room\n")

# get private key, public key and n using RSA
private_key, public_key, n = get_keys()
# send n and the public key to the server
s.send(str(n).encode())
s.send(str(public_key).encode())

while True:
    # receive encrypted GOST key
    encrypted_key_client = s.recv(1024).decode()

    # decrypt the encrypted GOST key using RSA decryption
    decrypted_key = RSA_decrypt(encrypted_key_client, private_key, n)

    # receive the GOST encrypted message and signature
    message = s.recv(1024).decode()
    signature = s.recv(1024).decode()

    # try to verify signature
    if verifyMessage(signature.split()):  # split creates an array from the signature string
        print("Message is safe")
        # decrypt GOST encrypted message
        message = GOST_decrypt(message, decrypted_key)
        print(s_name, ":", message)
    else:
        print("Message is not safe, signature is invalid!!!!")


    message = input(str("Me : "))
    if message == "[e]":
        message = "Left chat room!"
        s.send(message.encode(1024))
        print("\n")
        break
    s.send(message.encode())
