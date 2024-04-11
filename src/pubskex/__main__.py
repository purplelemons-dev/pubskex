# from . import generate_keys, armor_public_key, encrypt_message, armor_private_key

# public, private = generate_keys()
# message = "Hello, world. This message was encrypted using purplelemons-dev's PUBSKEX!"
# print(f"Original message: {message}")
# encrypted_message = encrypt_message(message, armor_public_key(public))
# print(f"Encrypted message: {encrypted_message}")

from . import decrypt_message

with open("message.pubskex", "r") as f:
    message = f.read()
with open("key", "r") as f:
    private = f.read()

print(decrypt_message(message, private))
