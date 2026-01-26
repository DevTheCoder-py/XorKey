import hashlib
import hmac
import string
from xorkey.utils import *
ASCII_CHARS = string.ascii_letters + string.digits + string.punctuation
def generate_keystream(password: str, length: int, salt: bytes = b"") -> str:
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        200_000
    )
    
    keystream = b""
    counter = 0
    
    # Generate blocks until we have enough
    while len(keystream) < length:
        counter_bytes = counter.to_bytes(4, "big")
        block = hmac.new(key, counter_bytes, hashlib.sha256).digest()
        keystream += block
        counter += 1
    
    # Truncate to exact length needed
    keystream = keystream[:length]  # Add this line
    
    ascii_stream = "".join(ASCII_CHARS[b % len(ASCII_CHARS)] for b in keystream)
    return ascii_stream
def encryptAutoGenandPass(string):
    msgBin = stringToBinStr(string)
    password = random_string(len(string))
    passwordBin = stringToBinStr(password)
    encryptedMsg = Xor2BinStrings(passwordBin, msgBin)
    encryptedMsgASCII = binary_to_ascii(encryptedMsg)
    return encryptedMsgASCII, password
def decryptAutoGenandPass(string, password):
    encryptedBin = stringToBinStr(string)
    passwordBin = stringToBinStr(password)
    originalMsg = binary_to_ascii(Xor2BinStrings(encryptedBin, passwordBin))
    return originalMsg


