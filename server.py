import socket
import threading
from hashlib import sha256

from utils import (decode_public_key, decrypt_message, encode_public_key,
                   encrypt_message, make_key_pair)


class Server:

    def __init__(self, port: int) -> None:
        self.host = "127.0.0.1"
        self.port = port
        self.clients = []
        self.public_key_lookup = {}
        self.username_lookup = {}
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def start(self):
        self.s.bind((self.host, self.port))
        self.s.listen(100)

        # generate keys ...
        self.public_key, self.private_key = make_key_pair()
        while True:
            c, addr = self.s.accept()
            username = c.recv(1024).decode()
            print(f"{username} tries to connect")
            self.broadcast(f"new person has joined: {username}")
            self.username_lookup[c] = username
            self.clients.append(c)

            c.send(encode_public_key(self.public_key))
            client_public_key = decode_public_key(c.recv(1024))

            self.public_key_lookup[c] = client_public_key

            threading.Thread(
                target=self.handle_client,
                args=(
                    c,
                    addr,
                ),
            ).start()

    def broadcast(self, msg: str):
        hash_256 = sha256(msg.encode())
        for client in self.clients:
            message = encrypt_message(self.public_key_lookup[client], msg.encode())
            message = hash_256.digest() + message
            client.send(message)

    def handle_client(self, c: socket, addr):
        while True:
            msg = c.recv(1024)
            hash_256 = msg[:32]
            msg = msg[32:]
            msg = decrypt_message(self.public_key, self.private_key, msg)
            for client in self.clients:
                if client != c:
                    encrypted = encrypt_message(self.public_key_lookup[client], msg)
                    client.send(hash_256 + encrypted)


if __name__ == "__main__":
    s = Server(9002)
    s.start()
