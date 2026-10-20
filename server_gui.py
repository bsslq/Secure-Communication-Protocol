import socket, json, base64, threading
import tkinter as tk
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HOST = "127.0.0.1"
PORT = 4444

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

def log(text):
    output.insert(tk.END, text + "\n")
    output.see(tk.END)

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

def start_server():
    def server_thread():
        try:
            log(f"[+] Server started on {HOST}:{PORT}")
            log("[+] Waiting for client...\n")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind((HOST, PORT))
                s.listen(1)
                conn, addr = s.accept()
                with conn:
                    log(f"[+] Client connected: {addr}\n")
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
                    log("========== SERVER DATA ==========")
                    log("Public Key:")
                    log(public_pem.decode())
                    log("Encrypted AES Key:")
                    log(base64.b64encode(encrypted_aes_key).decode())
                    log("Decrypted AES Key:")
                    log(base64.b64encode(aes_key).decode())
                    log("Nonce:")
                    log(base64.b64encode(nonce).decode())
                    log("Cipher Text:")
                    log(base64.b64encode(ciphertext).decode())
                    log("Plain Text:")
                    log(plaintext.decode())
                    log("=================================")
        except Exception as e:
            log(f"[!] Error: {e}")
    threading.Thread(target=server_thread, daemon=True).start()

root = tk.Tk()
root.title("Hybrid Secure Protocol - Server")
root.geometry("900x650")
title = tk.Label(root, text="Secure Communication Server", font=("Arial", 18, "bold"))
title.pack(pady=10)
btn = tk.Button(root, text="Start Server", font=("Arial", 12), command=start_server)
btn.pack(pady=5)
output = tk.Text(root, font=("Consolas", 10))
output.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
root.mainloop()
