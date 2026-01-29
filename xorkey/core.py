import hashlib
import hmac
import string
import ast
from xorkey.utils import *
ASCII_CHARS = string.ascii_letters + string.digits + string.punctuation
def generate_keystream(password: str, length: int, salt: bytes = b""):
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
    keystream = keystream[:length]
    #encodedKeyStream = encode_base64(keystream)
    #ascii_stream = "".join(ASCII_CHARS[b % len(ASCII_CHARS)] for b in keystream)
    return keystream
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

class AuthError(Exception):
    """Raised when message authenticity verification fails."""
    pass

def encryptWithMode(string, mode="pure"):
    encrypted, password = encryptAutoGenandPass(string)
    
    if mode == "OTP":
        # Use bytes to avoid encoding issues
        mac = hmac.new(password.encode(), encrypted.encode(), hashlib.sha256).hexdigest()
        encrypted = f"{encrypted}:{mac}"
    
    return encrypted, password

def decryptWithMode(encryptedMsg, password: str, mode: str):
    if mode == "OTP" or "auto":
        try:
            encrypted, received_mac = encryptedMsg.rsplit(":", 1)
        except ValueError:
            raise ValueError("Invalid format: missing MAC")
        
        # Compute expected MAC
        expected_mac = hmac.new(password.encode(), encrypted.encode(), hashlib.sha256).hexdigest()
        
        # Compare securely
        if not hmac.compare_digest(received_mac, expected_mac):
            raise AuthError("Message authentication failed: tampered or corrupted")
        
        # Only decrypt if MAC verified
        return decryptAutoGenandPass(encrypted, password)
    
    elif mode == "pure":
        # No authentication check in pure mode
        return decryptAutoGenandPass(encryptedMsg, password)
    
    else:
        raise ValueError("Unknown mode")
def encryptCustomPass(msg, Pass) -> str:
    salt = generate_salt()
    msgBytes = msg.encode("utf-8")
    keystreamBytes = generate_keystream(Pass, len(msgBytes), salt)
    msgBin = bytesToBinStr(msgBytes)
    keystreamBin = bytesToBinStr(keystreamBytes)
    encryptedBin = Xor2BinStrings(keystreamBin, msgBin)
    encrypted = binStrToBytes(encryptedBin)
    saltB64 = encode_base64(salt)
    assert len(msgBin) == len(keystreamBin), (
    f"Length mismatch: msgBin={len(msgBin)}, keystreamBin={len(keystreamBin)}") # specific to this only due to reliance on bytes format
    return f"{saltB64}:{encrypted}"

def decryptCustomPass(msg: str, Pass: str) -> str:
    Esalt, encryptedMsg = msg.split(":", 1)
    try:
        salt = base64.b64decode(Esalt.encode("utf-8"))
        encryptedMsgBytes = ast.literal_eval(encryptedMsg)
        encryptedBin = bytesToBinStr(encryptedMsgBytes)
        keystreamBytes = generate_keystream(Pass, len(encryptedMsgBytes), salt)
        keystreamBin = bytesToBinStr(keystreamBytes)
        assert len(encryptedBin) == len(keystreamBin), (
            f"Length mismatch: encryptedBin={len(encryptedBin)}, keystreamBin={len(keystreamBin)}"
        )
        decryptedBin = Xor2BinStrings(encryptedBin, keystreamBin)
        decryptedBytes = binStrToBytes(decryptedBin)
        decryptedMsg = decryptedBytes.decode("utf-8")
    except UnicodeDecodeError:
        print("Decryption Failed: Is password correct?")
        exit()

    return decryptedMsg

#print(encryptCustomPass("yotejhieeiieinmdkdfggie", "hi"))

