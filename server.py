# server.py
import time, socket, sys

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

while True:
    message = input(str("Me : "))
    text,my_GOST = GOST_init(message)
    message = GOST_encrypt(text,my_GOST)
    encrypt_msg = " ".join(message)
    # for t in message:
    #     encrypt_msg = str(t)
    print(encrypt_msg)

    if message == "[e]":
        message = "Left chat room!"
        conn.send(message.encode())
        print("\n")
        break

    signature = signMessage(encrypt_msg)
    conn.send(encrypt_msg.encode())
    conn.send(signature.encode())
    message = conn.recv(1024)
    message = message.decode()
    print(s_name, ":", message)
