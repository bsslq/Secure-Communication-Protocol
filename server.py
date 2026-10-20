import socket, json, base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HOST = "0.0.0.0"
PORT = 4444

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

def recv_json(conn):
    data = b""
    while True:
        chunk = conn.recv(4096)
        if not chunk:
            break
        data += chunk
        try:
            return json.loads(data.decode())
        except json.JSONDecodeError:
            continue

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen(1)
    print(f"[+] Server listening on {HOST}:{PORT}")

    conn, addr = s.accept()
    with conn:
        print(f"[+] Client connected: {addr}")
        conn.sendall(public_pem)
        package = recv_json(conn)

        encrypted_aes_key = base64.b64decode(package["encrypted_aes_key"])
        nonce = base64.b64decode(package["nonce"])
        ciphertext = base64.b64decode(package["ciphertext"])

        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        print("\n--- SERVER RECEIVED DATA ---")
        print("public key:")
        print(public_pem.decode())
        print("encrypted aes key:")
        print(base64.b64encode(encrypted_aes_key).decode())
        print("decrypted aes key:")
        print(base64.b64encode(aes_key).decode())
        print("nonce:")
        print(base64.b64encode(nonce).decode())
        print("cipher text:")
        print(base64.b64encode(ciphertext).decode())
        print("plain text:")
        print(plaintext.decode())
