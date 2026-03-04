import sys
import socket
from os import _exit as quit

def main():
    if len(sys.argv) != 5:
        print("usage: python3 %s <listen_port> <bob_host> <bob_port> <mode>" % sys.argv[0])
        quit(1)

    listen_port = int(sys.argv[1])
    bob_host = sys.argv[2]
    bob_port = int(sys.argv[3])
    mode = sys.argv[4]

  
    # listen for Alice
    listenfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listenfd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listenfd.bind(('', listen_port))
    listenfd.listen(1)

    print("Mallory listening on port", listen_port)

    (alice_conn, addr) = listenfd.accept()
    print("Alice connected from", addr)

    # connect to Bob
    bob_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bob_conn.connect((bob_host, bob_port))
    print("Connected to Bob")

    stored_messages = []

    while True:
        msg = alice_conn.recv(1024)
        
        if not msg:
            print("Alice disconnected")
            break
        
        intercepted = msg.decode(errors="replace")
        print("\nMallory intercepted:")

        if mode == "none":
            print("Plaintext:", msg.decode(errors="replace"))

        elif mode == "enc":
            print("Ciphertext:", msg)

        elif mode == "mac":
            message = msg[:-32]
            tag = msg[-32:]
            print("Plaintext:", message.decode(errors="replace"))
            print("Tag:", tag)

        elif mode == "encmac":
            ciphertext = msg[:-32]
            tag = msg[-32:]
            print("Ciphertext:", ciphertext)
            print("Tag:", tag)

        else:
            print("Invalid mode")

        action = input("[f]orward / [m]odify / [d]elete / [r]eplay: ")

        if action == "f":
            bob_conn.sendall(msg)
            stored_messages.append(msg)

        elif action == "m":
            if len(msg) > 0:
                modified = bytearray(msg)
                modified[0] ^= 1  # flip first bit
                bob_conn.sendall(bytes(modified))
                print("Bit flipped.")

        elif action == "d":
            print("Message deleted.")
        
        elif action == "r":
            if len(stored_messages) >= 2:
                bob_conn.sendall(stored_messages[-1])
                print("Replayed previous message.")
            else:
                print("No previous message to replay.")

        else:
            print("Invalid option.")

    alice_conn.close()
    bob_conn.close()
    listenfd.close()


if __name__ == "__main__":
    main()