import sys
import socket
import os
from os import _exit as quit
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def compute_hmac(key, message):
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    return h.finalize()

def verify_hmac(key, message, tag):
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    try:
        h.verify(tag)
        return True
    except Exception:
        return False

def aes_encrypt(key, plaintext):
    iv = os.urandom(16)  # 16-byte IV
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv + ciphertext
    
def main():
    if len(sys.argv) != 4:
        print("usage: python3 %s <host> <port> <mode>" % sys.argv[0])
        quit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])
    mode = sys.argv[3]

    clientfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    clientfd.connect((host, port))

    print("Connected to server in mode:", mode)

    # enc mode
    if mode == "enc":
        # Load Bob's public key
        with open("bob_public.pem", "rb") as f:
            bob_public_key = serialization.load_pem_public_key(f.read())

        # Generate AES key
        aes_key = os.urandom(32)

        # Encrypt AES key
        encrypted_key = bob_public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Send encrypted AES key
        clientfd.sendall(encrypted_key)

        print("AES key sent to Bob.")

    # plaintext
    elif mode == "none":
        pass
    
    # mac
    elif mode == "mac":

        with open("bob_public.pem", "rb") as f:
            bob_public_key = serialization.load_pem_public_key(f.read())

        shared_key = os.urandom(32)

        encrypted_key = bob_public_key.encrypt(
            shared_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        clientfd.sendall(encrypted_key)

        print("Shared MAC key sent to Bob.")
    
    # encmac
    elif mode == "encmac":
        with open("bob_public.pem", "rb") as f:
            bob_public_key = serialization.load_pem_public_key(f.read())

            shared_key = os.urandom(32)

            encrypted_key = bob_public_key.encrypt(
                shared_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
            )
        )

        clientfd.sendall(encrypted_key)

        print("Shared key sent to Bob (encmac mode).")

    else:
        print("Unknown mode:", mode)
        quit(1)

    # message loop
    while True:
        msg = input("Enter message: ")

        if mode == "none":
            clientfd.send(msg.encode())

        elif mode == "enc":
            encrypted = aes_encrypt(aes_key, msg.encode())
            clientfd.send(encrypted)
        elif mode == "mac":
            message_bytes = msg.encode()
            tag = compute_hmac(shared_key, message_bytes)
            # print("Sending:", message_bytes + tag)
            clientfd.send(message_bytes + tag)
        elif mode == "encmac":
            ciphertext = aes_encrypt(shared_key, msg.encode())
            tag = compute_hmac(shared_key, ciphertext)
            clientfd.send(ciphertext + tag)

    clientfd.close()


if __name__ == "__main__":
    main()