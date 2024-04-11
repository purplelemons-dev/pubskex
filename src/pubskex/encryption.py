from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from os import urandom
import base64


class AESMessage:
    def __init__(self, cipher_text: str, key: bytes, iv: bytes, tag: bytes):
        self.cipher_text = cipher_text
        self.key = key
        self.iv = iv
        self.tag = tag
        # first 64 chars are key, next 32 chars are iv, last 32 chars are tag
        self.hexidecimal = key.hex() + iv.hex() + tag.hex()

    def decrypt(self) -> str:
        cipher = Cipher(algorithms.AES(self.key), modes.GCM(self.iv))
        decryptor = cipher.decryptor()
        bytes_cipher_text = base64.b64decode(self.cipher_text)
        plain_text = decryptor.update(bytes_cipher_text) + decryptor.finalize_with_tag(
            self.tag
        )
        return plain_text.decode()


def generate_AES_message(message: str) -> AESMessage:
    "Generate a random AES key"
    key = urandom(32)
    iv = urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(message.encode()) + encryptor.finalize()
    cipher_text = base64.b64encode(cipher_text).decode()
    return AESMessage(cipher_text, key, iv, encryptor.tag)


if __name__ == "__main__":
    from random import getrandbits as grb

    message = str(grb(1024))
    aes_message = generate_AES_message(message)
    print(aes_message.cipher_text)
    print(aes_message.hexidecimal)
    # print(aes_message.decrypt())
