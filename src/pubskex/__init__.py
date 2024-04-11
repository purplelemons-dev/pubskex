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


def pubskex_keygen(filename: str = None):
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


