import sys
import socket
from os import _exit as quit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives import hashes
import os

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

def aes_decrypt(key, data):
    iv = data[:16]
    ciphertext = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext
    
def main():
    if len(sys.argv) != 3:
        print("usage: python3 %s <port> <mode>" % sys.argv[0])
        quit(1)

    port = int(sys.argv[1])
    mode = sys.argv[2]

    listenfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listenfd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listenfd.bind(('', port))
    listenfd.listen(1)

    print("Bob listening on port", port, "in mode:", mode)

    (connfd, addr) = listenfd.accept()
    print("Connection from", addr)

    # mode none
    if mode == "none":
        while True:
            msg = connfd.recv(1024)
            if not msg:
                break
            print("Received:", msg.decode())

    # mode enc
    elif mode == "enc":

        encrypted_key = connfd.recv(1024)

        with open("bob_private.pem", "rb") as f:
            bob_private_key = serialization.load_pem_private_key(
                f.read(),
                password=None
            )

        aes_key = bob_private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        print("AES key established.")

        while True:
            msg = connfd.recv(1024)
            if not msg:
                break

            try:
                plaintext = aes_decrypt(aes_key, msg)
                print("Decrypted:", plaintext.decode(errors="replace"))
            except Exception as e:
                print("Decryption error:", e)

    #mac mode

    elif mode == "mac":
        encrypted_key = connfd.recv(1024)
        with open("bob_private.pem", "rb") as f:
            bob_private_key = serialization.load_pem_private_key(
                f.read(),
                password=None
            )

        shared_key = bob_private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        print("Shared MAC key established.")

        while True:
            msg = connfd.recv(1024)
            if not msg:
                break

            message = msg[:-32]
            tag = msg[-32:]

            if verify_hmac(shared_key, message, tag):
                print("Verified:", message.decode(errors="replace"))
            else:
                print("Tampering detected!")

    # encmac mode
    elif mode == "encmac":

        encrypted_key = connfd.recv(1024)

        with open("bob_private.pem", "rb") as f:
            bob_private_key = serialization.load_pem_private_key(
                f.read(),
                password=None
            )

        shared_key = bob_private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        print("Shared key established (encmac mode).")

        while True:
            msg = connfd.recv(1024)
            if not msg:
                break

            ciphertext = msg[:-32]
            tag = msg[-32:]

            if not verify_hmac(shared_key, ciphertext, tag):
                print("Tampering detected!")
                continue

            plaintext = aes_decrypt(shared_key, ciphertext)
            print("Decrypted:", plaintext.decode(errors="replace"))

    else:
        print("Unknown mode:", mode)
        quit(1)

    connfd.close()
    listenfd.close()


if __name__ == "__main__":
    main()