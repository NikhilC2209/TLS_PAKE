import socket
from utils import *
import json
from base64 import b64encode, b64decode

HOST = '127.0.0.1'
PORT = 65432     
PRF_key_path = "server_data/PRF_key.pem"

server_cert, server_pvkey = load_cert_and_key()
server_pubkey = server_cert.public_key()

data = load_savedrw("server_data/saved_rw.json")

s = create_server_socket(PORT)
conn, addr = s.accept()

with conn:
    print(f"Connected with client at fd: {conn.fileno()} at {addr}\n\n")
    a = conn.recv(1024)
    print("Server received a ---> H1(pw)^r from client")
    print(f"Data received from client(hex): {a.hex()}\n\n")
    
    k = return_k(PRF_key_path)
    b = server_step1(a, k)
    conn.send(b)
    print("Server first step: Server sends back b ---> a^k")
    print(f"Data sent(hex): {b.hex()}\n\n")

    c = conn.recv(1024)
    print("Server received c ---> H2(b^1/r) from client")
    print(f"Data received from client(hex): {c.hex()}\n\n")
        
    print(f"Now server checks this c value against the hash value already stored in saved_rw.json")

    if c==data["alice"]:
        print("Auth successful!")

    with open("server_data/server_cert.pem", "rb") as fp:
        cert = fp.read()

    print("Server inititates next step by sending its self-signed certificate:\n\n")
    conn.send(cert)
