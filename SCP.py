from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import base64

#first generate RSA Public K and Private K
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()
#input from the user
message = input("Enter the message: ").encode()
#generate aes key
aes_key = os.urandom(32)
#encrypt aes key using the RSA Public key
def encrypt_aes_key(aes_key , public_key):
    encrypted_aes_key = public_key.encrypt(aes_key,padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))
    return encrypted_aes_key
encrypted_aes_key = encrypt_aes_key(aes_key, public_key)
#decrypt the aes key using RSA Private key
def decrypt_aes_key(encrypted_aes_key , private_key):
    decrypted_aes_key = private_key.decrypt(encrypted_aes_key,padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))
    return decrypted_aes_key
decrypted_aes_key = decrypt_aes_key(encrypted_aes_key, private_key)
#encrypt the message
nonce = os.urandom(16)
def encrypt_message (message):
    aesgsm=AESGCM(aes_key)
    ciphertext = aesgsm.encrypt(nonce,message,None)
    return ciphertext
#decrypt the message
def decrypt_message (ciphertext):
    aesgsm=AESGCM(decrypt_aes_key(encrypted_aes_key, private_key))
    plaintext = aesgsm.decrypt(nonce,ciphertext,None)
    return plaintext
encrypted_message = encrypt_message(message)
decrypted_message = decrypt_message(encrypted_message)
print("aes key: " + base64.b64encode(aes_key).decode())
print("encrypted aes key: " + base64.b64encode(encrypted_aes_key).decode())
print("decrypted aes key: " + base64.b64encode(decrypted_aes_key).decode())
print("nonce: " + base64.b64encode(nonce).decode())
print("ciphet text: "+ base64.b64encode(encrypted_message).decode())
print("plain text: "+decrypted_message.decode())
