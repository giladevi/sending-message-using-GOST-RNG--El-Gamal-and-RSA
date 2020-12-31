# client.py
import time, socket, sys
from RSA import get_keys
from elsig import verifyMessage
from gost import *
from Crypto.Util.number import bytes_to_long, long_to_bytes

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

private_key, public_key, n = get_keys()
s.send(str(n).encode())
s.send(str(public_key).encode())  # send the public key to the server before everything

while True:
    message = s.recv(1024).decode()
    encrypted_key = s.recv(1024).decode()
    print("encrypted key client={}".format(encrypted_key))
    signature = s.recv(1024).decode()
    if verifyMessage(signature.split()):  # creates an array from the signature string
        print("Message is safe")
        message = GOST_decrypt(message)
        print(s_name, ":", message)
    else:
        print("Message is not safe, signature is invalid!!!!")
    message = input(str("Me : "))
    if message == "[e]":
        message = "Left chat room!"
        s.send(message.encode(1024))
        print("\n")
        break
    s.send(message.encode(1024))
