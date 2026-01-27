import secrets
import string
UserInput = input()
def random_string(length):
    all_printable = string.printable

# Filter out whitespace characters
    chars = [c for c in all_printable if not c.isspace()] #add all possible assci 8 bit characters
    return ''.join(secrets.choice(chars) for _ in range(length)) #generate random

binarr = []
for i in UserInput:
    binarr += format(ord(i), "08b")
key = random_string(len(UserInput))
keyarr = []
for i in key:
    keyarr += format(ord(i), "08b")
print(type(binarr))
print(binarr)
bino = "".join(binarr)
keyo = "".join(keyarr)
print(bino)
print(keyo)
result = ""
for bit1, bit2 in zip(bino,keyo):
    result += str(int(bit1)^int(bit2))
print(f"result: {result}")
resultAscii = ""
for i in range(0, len(result), 8):
    byte = result[i:i+8]
    resultAscii += chr(int(byte, 2))

print(repr(resultAscii))
