import socket
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
import os
import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import padding
from hashlib import sha256
from pprint import pprint
from sympy import mod_inverse

def create_client_socket(port):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect(('localhost', port))
	return s

def sample_r():
    private_key = Ed25519PrivateKey.generate()

    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    r = int.from_bytes(public_key_bytes, byteorder='big')
    #print(f"{r} is the random value on ed25519 curve")
    return r

def client_step1(pw, r):
    CURVE_ORDER = 2**252 + 27742317777372353535851937790883648493

    H1 = sha256(pw).digest()
    H1 = int.from_bytes(H1, byteorder='big') % CURVE_ORDER
    H1 = pow(H1, r, CURVE_ORDER)
    H1 = H1.to_bytes(32, byteorder='big')
    
    return H1

def mod_inv_r(r):
    CURVE_ORDER = 2**252 + 27742317777372353535851937790883648493
    inv_r = mod_inverse(r, CURVE_ORDER)

    return inv_r

def client_step2(b, r):
    CURVE_ORDER = 2**252 + 27742317777372353535851937790883648493
    
    inv_r = mod_inv_r(r)
    b = int.from_bytes(b, byteorder='big') % CURVE_ORDER
    c = pow(b, inv_r, CURVE_ORDER)

    c = c.to_bytes(32, byteorder='big')
    H2 = sha256(c).digest()

    return H2

def load_cert(cert_path):
    with open(cert_path, "rb") as fp:
        cert_data = fp.read()

    cert = x509.load_pem_x509_certificate(cert_data)
    return cert

def verify_cert(cert):
    public_key = cert.public_key()

    try:
        public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

    except Exception as e:
        print(f"Exception ocurred: {e}")
        return False

    return True

### SERVER FUNCTIONS

def load_userdata(json_path):
    with open(json_path, "r") as f:
        data = json.load(f)
    return data["users"]

def load_savedrw(json_path):
    with open(json_path, "r") as f:
        data = json.load(f)
    return data

def return_k(PRF_key_path):
    with open(PRF_key_path, "rb") as fp:
        pv_bytes = fp.read()

    PRF_key = serialization.load_pem_private_key(
        pv_bytes,
        password=None,
    )  

    pv_bytes = PRF_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    ) 

    k = int.from_bytes(pv_bytes, byteorder="big")
    return k

def server_step1(a, k):
    CURVE_ORDER = 2**252 + 27742317777372353535851937790883648493
    a = int.from_bytes(a, byteorder='big')
    b = pow(a, k, CURVE_ORDER)
    return b.to_bytes(32, byteorder='big')

def save_rw(json_path, PRF_key_path):
    data = load_userdata(json_path)
    k = return_k(PRF_key_path)

    H1 = sha256()     
    H2 = sha256()    

    CURVE_ORDER = 2**252 + 27742317777372353535851937790883648493

    for user in data:
        pw_bytes = data[user].encode()
        H1.update(pw_bytes)
        h = H1.digest()
        h = int.from_bytes(h, byteorder='big') % CURVE_ORDER
        h = pow(h, k, CURVE_ORDER)

        h = h.to_bytes(32, byteorder='big')
        H2.update(h)
        h = H2.digest()
        data[user] = h.hex()

    with open("server_data/saved_rw.json", "w") as fp:
        json.dump(data, fp, indent=4)
    pprint(data)

def create_server_socket(port):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.bind(('localhost', port))
	s.listen(1)
	print("Server up and running!")
	return s

def gen_ss_cert():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Arizona"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Tempe"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"CSE539_Server"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).sign(key, hashes.SHA256())
    return cert, key

def save_cert_and_key(cert, key, path="server_data"):

    cert_path = os.path.join(path, "server_cert.pem")
    key_path = os.path.join(path, "server_key.pem")

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    print(f"Saved server certificate and key at {path}")

def load_cert_and_key(path="server_data"):
    
    cert_path = os.path.join(path, "server_cert.pem")
    key_path = os.path.join(path, "server_key.pem")

    with open(cert_path, "rb") as fp:
        cert_data = fp.read()
    cert = x509.load_pem_x509_certificate(cert_data)

    with open(key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )

    return cert, private_key

def gen_prf_key(path="server_data"):

    key_path = os.path.join(path, "PRF_key.pem")

    private_key = Ed25519PrivateKey.generate()
    print(private_key)
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    print(f"Saved PRF key at: {key_path}")
