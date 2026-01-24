import secrets
import string
def Xor2BinStrings(message, key):
    # although it implies it must me a msg and key, it will work with any as long as the bins are the same len 
    result = ""
    for bit1, bit2 in zip(message, key):
        result += str(int(bit1)^int(bit2))
    return result


def random_string(length):
    chars = string.ascii_letters + string.digits + string.punctuation #add all possible assci 8 bit characters
    return ''.join(secrets.choice(chars) for _ in range(length)) #generate random

def stringToBinStr(string):
    result = ""
    for i in string:
        result += format(ord(i), '08b')
    return result

def generate_salt(length: int = 16) -> bytes:
    return secrets.token_bytes(length)

#print(Xor2BinStrings("01011111111", "011010101010"))


