import socket, json, base64, os
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HOST = "127.0.0.1"
PORT = 4444

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    public_pem = s.recv(4096)
    public_key = serialization.load_pem_public_key(public_pem)
    message = input("Enter message: ").encode()

    aes_key = os.urandom(32)
    nonce = os.urandom(12)

    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, message, None)

    package = {
        "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }

    s.sendall(json.dumps(package).encode())
    print("[+] Encrypted message sent.")
