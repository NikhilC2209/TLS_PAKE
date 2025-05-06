import socket
from utils import *
from spake2 import SPAKE2_A


HOST = '127.0.0.1'
PORT = 65432

data = b'Helllooooooo'
password = b"mysecretpassword"
idA = b"alice"
idB = b"bob"

A = SPAKE2_A(password)
msg1 = A.start()

s = create_client_socket(PORT)
s.send(msg1)

print(f'Data sent: {msg1.hex()}')

recv_data = s.recv(1024)

print(f'Data received: {recv_data.hex()}')
