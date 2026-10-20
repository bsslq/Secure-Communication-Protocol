import socket, json, base64, os
import tkinter as tk
from tkinter import messagebox
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HOST = "127.0.0.1"
PORT = 4444

def send_message():
    message = message_entry.get("1.0", tk.END).strip()
    if not message:
        messagebox.showwarning("Warning", "Please enter a message")
        return

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            public_pem = s.recv(4096)
            public_key = serialization.load_pem_public_key(public_pem)
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
            ciphertext = aesgcm.encrypt(nonce, message.encode(), None)
            package = {
                "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode(),
                "nonce": base64.b64encode(nonce).decode(),
                "ciphertext": base64.b64encode(ciphertext).decode()
            }
            s.sendall(json.dumps(package).encode())
            messagebox.showinfo("Success", "Encrypted message sent successfully")
    except Exception as e:
        messagebox.showerror("Error", str(e))

root = tk.Tk()
root.title("Hybrid Secure Protocol - Client")
root.geometry("900x650")

title = tk.Label(root, text="Secure Communication Client", font=("Arial", 18, "bold"))
title.pack(pady=10)
label = tk.Label(root, text="Enter Message:", font=("Arial", 12))
label.pack()
message_entry = tk.Text(root, height=5, font=("Arial", 12))
message_entry.pack(fill=tk.X, padx=10, pady=5)
send_btn = tk.Button(root, text="Encrypt & Send", font=("Arial", 12), command=send_message)
send_btn.pack(pady=10)
output = tk.Text(root, font=("Consolas", 10))
output.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
root.mainloop()
