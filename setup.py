from utils import *

if __name__ == "__main__":
    cert, key = gen_ss_cert()
    save_cert_and_key(cert, key)

    gen_prf_key()
    save_rw("users.json", "server_data/PRF_key.pem")
