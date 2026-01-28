from xorkey.core import *
from xorkey.utils import *
import argcomplete
import argparse
import sys
from time import sleep
import os
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
            " - pure: Same as OTP but no encoding or authenthication feautures allowing you to use pure binary\n"
            "  - OTP: Standard base64 encoded output. DEFAULT\n"
            "  - personal: Use your own password [Still very secure]\n"
            f"  - auto: Automatically detect the format during decryption {GREEN}(default){RESET}."
        )
    )
    argcomplete.autocomplete(parser)
    args = parser.parse_args()
    print(f"DEBUG: args.format is {args.format}")

    #if encrypt mode:
    if args.encrypt:
        autoState = False
        encryptedMsg = "Encryption Failed"
        Pass = "Encryption Failed"
        if args.format == "auto": autoState = True
        if args.format == "auto" or args.format == "OTP":
            UsrInputStr2Encrypt = args.encrypt
            encryptedMsgandPass = encryptAutoGenandPass(UsrInputStr2Encrypt)
            encryptedMsg = str(encryptedMsgandPass[0])
            Pass = str(encryptedMsgandPass[1])
            encryptedMsg = base64.b64encode(encryptedMsg.encode('latin-1')).decode('utf-8') 
        if args.format == "pure":
            UsrInputStr2Encrypt = args.encrypt
            encryptedMsgandPass = encryptAutoGenandPass(UsrInputStr2Encrypt)
            encryptedMsg = repr(encryptedMsgandPass[0])
            Pass = repr(encryptedMsgandPass[1])
        if args.format == "personal":
            UsrInputStr2Encrypt = args.encrypt
            Pass = input("Enter password for encryption:\n")
            encryptedMsg = encode_base64(encryptCustomPass(UsrInputStr2Encrypt, Pass)) + "<PERSONAL>"
            Pass = r'---\HIDDEN/---'

        print("encrypted:", encryptedMsg)
        print("Password:", Pass)
        if autoState: print(f"\n{RED}Format not specified, defaulted to OTP mode{RESET}")
        if args.format == "pure": print(f"{RED}Warning: Using pure mode is not very supported as it may result in truncation of text. Should work fine most of the time.{RESET}")

    #if decrypt mode
    elif args.decrypt:
        Decrypted = "decryption failed"
        autoState = False
        if args.format == "auto":
            autoState = True
            if "<PERSONAL>" in args.decrypt:
                args.decrypt = args.decrypt.removesuffix("<PERSONAL>")
                print("Detected personal mode")
                args.format = "personal"
            elif is_base64(args.decrypt):
                args.format = "OTP"
                print("Detected OTP mode")
            else:
                args.format = "pure"
                print("Detected pure mode")
        if args.format == "OTP":
            try:
                UsrInputStr2Decrypt = base64.b64decode(args.decrypt).decode('latin-1')
            except Exception as e:
                print(f"Decryption Error: Are you using the right format? DEBUG:{e}")
                exit()
            UsrInputPswd = input("Password?\n")
            Decrypted = decryptAutoGenandPass(UsrInputStr2Decrypt, UsrInputPswd)
        if args.format == "pure":
            UsrInputStr2Decrypt = decode_escape_sequences(args.decrypt) #convert repr to ascii; may result in obfuscation
            UsrInputPswd = input("Password?\n")
            Decrypted = decryptAutoGenandPass(UsrInputStr2Decrypt, UsrInputPswd)
        if args.format == "personal":
           UsrInputStr2Decrypt = decode_base64(args.decrypt)
           UsrInputPswd = input("Password?\n")
           Decrypted = decryptCustomPass(UsrInputStr2Decrypt, UsrInputPswd)

        
        print("Decrypting..")
        print(f"\nDecrypted message is:\n{RED}{Decrypted}{RESET}")
        if autoState: print(f"\n{RED}{args.format} mode was detected. If output was unexpected, try using -f to choose decryption method manually.")
        if args.format == "pure": print("\nNote: Due to the nature of pure mode, authenticity of message cannot be guaranteed.")
    else:
        print("No argument provided; Use -h to see manual")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('Interrupted')
        try:
            sys.exit(130)
        except SystemExit:
            os._exit(130)

