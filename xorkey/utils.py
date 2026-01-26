import secrets
import string
import codecs
import base64
def Xor2BinStrings(message, key):
    # although it implies it must me a msg and key, it will work with any as long as the bins are the same len 
    result = ""
    for bit1, bit2 in zip(message, key):
        result += str(int(bit1)^int(bit2))
    return result


def random_string(length):
    chars = string.ascii_letters + string.digits + string.punctuation #add all possible assci 8 bit characters
    chars = chars.translate(str.maketrans('', '', "\"'''""„‟‛‚❛❜❝❞〝〞〟＂＇`´"))
    return ''.join(secrets.choice(chars) for _ in range(length)) #generate random

def stringToBinStr(string):
    result = ""
    for i in string:
        result += format(ord(i), '08b')
    return result

def generate_salt(length: int = 16) -> bytes:
    return secrets.token_bytes(length)
def binary_to_ascii(bin_str):
    ascii_out = ""
    for i in range(0, len(bin_str), 8):
        byte = bin_str[i:i+8]
        ascii_out += chr(int(byte, 2))
    return ascii_out
def decode_escape_sequences(s):
    """Decode escape sequences in string, handling mixed content"""
    try:
        # First try: encode to bytes assuming it might have escape sequences
        # This handles strings like "\x08V::\x18-"
        return s.encode('utf-8').decode('unicode_escape')
    except:
        try:
            # Second try: use codecs for unicode escape
            return codecs.decode(s, 'unicode_escape')
        except:
            # If all else fails, return original
            return s#print(random_string(5000))
def is_base64(s: str) -> bool:
    try:
        return base64.b64encode(base64.b64decode(s)) == s.encode()
    except Exception:
        return False
def encode_base64(text: str) -> str:
    """Encode string to base64"""
    return base64.b64encode(text.encode('utf-8')).decode('utf-8')

def decode_base64(encoded: str) -> str:
    """Decode base64 to string"""
    return base64.b64decode(encoded.encode('utf-8')).decode('utf-8')


