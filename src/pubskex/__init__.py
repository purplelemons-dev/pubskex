# Public key (PK): RSA >= 2048 bits
# Message encrypted using AES-256-GCM (some key "A" generated)
# hash of original message appended to encrypted message
# key "A" is encrypted using "PK"

from .encryption import AESMessage, generate_AES_message
from .keygen import (
    armor_private_key,
    armor_public_key,
    dearmor_private_key,
    dearmor_public_key,
    PrivateKey,
    PublicKey,
    newkeys,
)
from rsa import encrypt as rsa_encrypt, decrypt as rsa_decrypt
from base64 import b64encode, b64decode


def generate_keys(filename: str = None) -> tuple[PublicKey, PrivateKey]:
    "prints results to console if filename is None, otherwise writes keys to files"
    public, private = newkeys(3072)
    public_armor = armor_public_key(public)
    private_armor = armor_private_key(private)

    if filename is None:
        print("\nPUBLIC KEY")
        print(public_armor)
        print("\nPRIVATE KEY")
        print(private_armor)
    else:
        with open(f"{filename}.pub", "w") as f:
            f.write(public_armor)
        with open(f"{filename}", "w") as f:
            f.write(private_armor)
    return public, private


def encrypt_message(message: str, armored_public_key: str) -> str:
    "Encrypt a message using a public key"
    aes_message = generate_AES_message(message)
    public_key = dearmor_public_key(armored_public_key)
    main_text = "<pubskex>\n<cipher-text>\n"
    main_text += aes_message.cipher_text
    main_text += "\n</cipher-text>\n<key>"

    key = aes_message.hexidecimal
    encrypted_key = rsa_encrypt(key.encode(), public_key)

    main_text += f"\n{b64encode(encrypted_key).decode()}"
    main_text += "\n</key>\n</pubskex>"
    return main_text


def decrypt_message(pubskex_text: str, armored_private_key: str) -> str:
    "Decrypt a message using a private key"
    pubskex = pubskex_text.split()
    idx = pubskex.index("<cipher-text>")
    ciphertext = pubskex[idx + 1]
    idx = pubskex.index("<key>")
    key = b64decode(pubskex[idx + 1])
    private_key = dearmor_private_key(armored_private_key)
    key = rsa_decrypt(key, private_key).decode()
    message = AESMessage(ciphertext, bytes.fromhex(key[:64]), bytes.fromhex(key[64:96]), bytes.fromhex(key[96:]))
    return message.decrypt()
