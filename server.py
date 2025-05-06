import socket
from utils import *
import json

HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 65432        # Port to listen on (non-privileged ports are > 1023)

def load_userdata(json_path):
	with open(json_path, "r") as f:
		data = json.load(f)
	return data["users"]

data = load_userdata("users.json")
print(data)

s = create_server_socket(PORT)
conn, addr = s.accept()

with conn:
    print(f"Connected with client at fd: {conn.fileno()} at {addr}")
    data = conn.recv(1024)
    print(f"Data received from client: {data.hex()}")
    conn.send(data)

