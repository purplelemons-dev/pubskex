from rsa import newkeys, PrivateKey, PublicKey
from hashlib import sha256


def dearmor_private_key(armor: str):
    "turns b64 string into a key"
    armor = armor.split("\n")
    idx = armor.index("<private-key>")
    n = int(armor[idx + 1], 16)
    e = int(armor[idx + 2], 16)
    d = int(armor[idx + 3], 16)
    p = int(armor[idx + 4], 16)
    q = int(armor[idx + 5], 16)
    reconstructed = b"\n".join(
        [
            hex(n)[2:].encode(),
            hex(e)[2:].encode(),
            hex(d)[2:].encode(),
            hex(p)[2:].encode(),
            hex(q)[2:].encode(),
        ]
    )
    # print(reconstructed)
    return PrivateKey(n, e, d, p, q)


def dearmor_public_key(armor: str):
    "turns b64 string into a key"
    armor = armor.split("\n")
    idx = armor.index("<public-key>")
    n = int(armor[idx + 1], 16)
    e = int(armor[idx + 2], 16)
    reconstructed = b"\n".join([hex(n)[2:].encode(), hex(e)[2:].encode()])
    # print(reconstructed)
    return PublicKey(n, e)


def armor_private_key(key: PrivateKey):
    "turns key into a b64 string"
    n, e, d, p, q = key.n, key.e, key.d, key.p, key.q
    armor = "<pubskex>\n<private-key>\n"
    bytes_n = hex(n)[2:].encode()
    bytes_e = hex(e)[2:].encode()
    bytes_d = hex(d)[2:].encode()
    bytes_p = hex(p)[2:].encode()
    bytes_q = hex(q)[2:].encode()
    key_armor = b"\n".join([bytes_n, bytes_e, bytes_d, bytes_p, bytes_q])
    armor += key_armor.decode()
    armor += "\n</private-key>\n</pubskex>"
    return armor


def armor_public_key(key: PublicKey):
    armor = "<pubskex>\n<public-key>\n"
    n, e = key.n, key.e
    bytes_n = hex(n)[2:].encode()
    bytes_e = hex(e)[2:].encode()
    key_armor = b"\n".join([bytes_n, bytes_e])
    armor += key_armor.decode()
    armor += "\n</public-key>\n</pubskex>"
    return armor


if __name__ == "__main__":
    public, private = newkeys(3072)
    print(f"public armor: {armor_public_key(public)}")
    print(f"private armor: {armor_private_key(private)}")
