import socket

def create_client_socket(port):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect(('localhost', port))
	return s

def create_server_socket(port):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.bind(('localhost', port))
	s.listen(1)
	print("Server up and running!")
	return s
