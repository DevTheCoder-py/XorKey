from xorkey.core import *
from xorkey.utils import *
import argcomplete
import argparse
import sys
from time import sleep
RED = "\033[31m"
RESET = "\033[0m"
GREEN = "\033[0;32m"
def main():
    parser = argparse.ArgumentParser(
        description="A command-line tool for XOR encryption and decryption.",
        #formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=40)
        formatter_class=argparse.RawTextHelpFormatter
        )
    parser.add_argument(
        "-e", "--encrypt",
        type=str,
        metavar="<TEXT>",
        help="Encrypt the given text. Use with -f to specify the output format."
    )
    parser.add_argument(
        "-d", "--decrypt",
        type=str,
        metavar="<CIPHER>",
        help="Decrypt the given ciphertext. Use with -f to specify the input format."
    )
    parser.add_argument(
        "-f", "--format",
        choices=['pure', 'OTP', 'personal', "auto"],
        default="auto",
        help=(
            f"{RED}Specify the encryption/decryption format[OPTIONAL]:\n{RESET} "
            " - pure: Raw encrypted output, no encoding.\n"
            "  - OTP: Standard base64 encoded output.\n"
            "  - personal: Use your own password [Still very secure]\n"
            f"  - auto: Automatically detect the format during decryption {GREEN}(default){RESET}."
        )
    )
    argcomplete.autocomplete(parser)
    args = parser.parse_args()
    print(f"DEBUG: args.format is {args.format}")
    if args.encrypt:
        encryptedMsg = "Encryption Failed"
        Pass = "Encryption Failed"
        if args.format == "auto" or args.format == "OTP":
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
        autoState = False
        if args.format == "auto":
            autoState = True
            if is_base64(args.decrypt):
                args.format = "OTP"
                print("Detected OTP mode")
            else:
                args.format = "pure"
                print("Detected pure mode")
        if args.format == "OTP":
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
