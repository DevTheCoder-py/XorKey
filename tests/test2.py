import hashlib
import hmac

def generate_keystream(password: str, length: int, salt: bytes = b"") -> bytes:
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        200_000
    )

    keystream = b""
    counter = 0
    while len(keystream) < length:
        counter_bytes = counter.to_bytes(4, "big")
        block = hmac.new(key, counter_bytes, hashlib.sha256).digest()
        keystream += block
        counter += 1

    return keystream[:length]


def xor_encrypt_decrypt(message: bytes, keystream: bytes) -> bytes:
    return bytes(m ^ k for m, k in zip(message, keystream))


message = b"Hello, XOR encryption!"
password = "mypassword123"
salt = b"unique_salt_here"

keystream = generate_keystream(password, len(message), salt)
ciphertext = xor_encrypt_decrypt(message, keystream)
decrypted = xor_encrypt_decrypt(ciphertext, keystream)

print("Original message: ", message)
print("Ciphertext bytes: ", ciphertext)
print("Decrypted message:", decrypted)

