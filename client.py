import socket
from utils import *
from base64 import b64encode, b64decode

HOST = '127.0.0.1'
PORT = 65432

user = "alice"
password = b"password123"
r = sample_r()

### AUTH PHASE

a = client_step1(password, r)

s = create_client_socket(PORT)
s.send(a)

print("\n\nFirst step: Client sends a ---> H1(pw)^r")
print(f'Data sent(hex): {a.hex()}\n\n')

b = s.recv(1024)

print("Client received b ---> a^k")
print(f'Data received(hex): {b.hex()}\n\n')

c = client_step2(b, r)
s.send(c)
print("Client second step: Client sends back c ---> H2(b^1/r)")
print(f'Data sent(hex): {c.hex()}\n\n')

### VERIFY SERVER CERTIFICATE

cert = s.recv(4096)
print("Certificate received by the client, now it will verify it\n\n")

cert_path = "client_data/client_cert.pem"

with open(cert_path, "wb") as fp:
    fp.write(cert)

cert = load_cert(cert_path)

if verify_cert(cert):
    print("Server certificate verified successfully!")
