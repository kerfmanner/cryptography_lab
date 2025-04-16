import socket
import threading
# importing library for hashing
from hashlib import sha256

from utils import (decode_public_key, decrypt_message, encode_public_key,
                   encrypt_message, make_key_pair)


class Client:
    def __init__(self, server_ip: str, port: int, username: str) -> None:
        self.server_ip = server_ip
        self.port = port
        self.username = username

    def init_connection(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.s.connect((self.server_ip, self.port))
        except Exception as e:
            print("[client]: could not connect to server: ", e)
            return

        self.s.send(self.username.encode())

        self.public_key, self.private_key = make_key_pair()
        encoded_public = encode_public_key(self.public_key)

        self.server_public_key = decode_public_key(self.s.recv(1024))
        self.s.send(encoded_public)

        message_handler = threading.Thread(target=self.read_handler, args=())
        message_handler.start()
        input_handler = threading.Thread(target=self.write_handler, args=())
        input_handler.start()

    def read_handler(self):
        while True:
            message = self.s.recv(1024)
            hash_256_sent = message[:32]
            encrypted_message = message[32:]

            decrypted_message = decrypt_message(
                self.public_key, self.private_key, encrypted_message
            )
            hash_256 = sha256(decrypted_message)
            if hash_256.digest() == hash_256_sent:
                print(decrypted_message.decode())
            else:
                print("message might be tampered (hash mismatch)")

    def write_handler(self):
        while True:
            message = input()
            message = "User " + '"' + self.username + '"' + " : " + message
            hash_256 = sha256(message.encode())

            encrypted_message = encrypt_message(
                self.server_public_key, message.encode()
            )
            hash_with_message = hash_256.digest() + encrypted_message

            self.s.send(hash_with_message)


if __name__ == "__main__":
    cl = Client("127.0.0.1", 9002, "b1")
    cl.init_connection()
