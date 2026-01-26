from xorkey.core import *
from xorkey.utils import *
import argcomplete
import argparse
import sys
from time import sleep
RED = "\033[31m"
RESET = "\033[0m"
def main():
    parser = argparse.ArgumentParser(description="A encryption software utilising XOR, pretty much unbreakable",
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument(
            "-e", "--encrypt",
            type=str,
            help = "Encrypt; Choice to use safe auto-generated pass-key(portable) or your own one(XorKey only)."
            )
    parser.add_argument(
            "-d", "--decrypt",
            type=str,
            help = "--decrypt [str]"
            )
    parser.add_argument(
            "-f", "--format",
            choices=['pure', 'normal', 'personal',"auto"],
            default="auto",
            help=("pure: raw encrypted output, no encoding;\n"
                  "normal: standard base64 encoded output (default);\n"
                  "personal: app-specific format;\n"
                  "auto: same as normal;"
                  )
            )
    argcomplete.autocomplete(parser)
    args = parser.parse_args()
    print(f"DEBUG: args.format is {args.format}")
    if args.encrypt:
        encryptedMsg = "Encryption Failed"
        Pass = "Encryption Failed"
        if args.format == "auto" or args.format == "normal":
            UsrInputStr2Encrypt = args.encrypt
            encryptedMsgandPass = encryptAutoGenandPass(UsrInputStr2Encrypt)
            encryptedMsg = str(encryptedMsgandPass[0])
            Pass = str(encryptedMsgandPass[1])
            encryptedMsg = base64.b64encode(encryptedMsg.encode('latin-1')).decode('utf-8')
        if args.format == "pure":
            UsrInputStr2Encrypt = args.encrypt
            encryptedMsgandPass = encryptAutoGenandPass(UsrInputStr2Encrypt)
            encryptedMsg = str(encryptedMsgandPass[0])
            Pass = str(encryptedMsgandPass[1])
        print("encrypted:", encryptedMsg)
        print("Password:", Pass)

    elif args.decrypt:
        Decrypted = "decryption failed"
        if args.format == "auto":
            if is_base64(args.decrypt):
                args.format = "normal"
                print("Detected normal mode")
            else:
                args.format == "pure"
        if args.format == "normal":
            UsrInputStr2Decrypt = base64.b64decode(args.decrypt).decode('latin-1')
            UsrInputPswd = input("Password?\n")
            Decrypted = decryptAutoGenandPass(UsrInputStr2Decrypt, UsrInputPswd)
        if args.format == "pure":
            UsrInputStr2Decrypt = args.decrypt
            UsrInputPswd = input("Password?\n")
            Decrypted = decryptAutoGenandPass(UsrInputStr2Decrypt, UsrInputPswd)
        print("Decrypting..")
        print(f"\nDecrypted message is:\n{RED}{Decrypted}{RESET}")
    else:
        print("No argument provided; Use -h to see manual")
if __name__ == "__main__":
    main()
