from xorkey.core import *
from xorkey.utils import *
import argcomplete
from getpass import getpass
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
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "-e", "--encrypt",
        nargs='?',
        const=True,
        default=None,
        metavar="<TEXT>",
        help="Encrypt the given text. If used with -f, the content of the file will be encrypted."
    )
    parser.add_argument(
        "-d", "--decrypt",
        nargs='?',
        const=True,
        default=None,
        metavar="<CIPHER>",
        help="Decrypt the given ciphertext. If used with -f, the content of the file will be decrypted."
    )
    parser.add_argument(
        "-m", "--mode",
        choices=['pure', 'OTP', 'personal', "auto"],
        default="auto",
        help=(
            f"{RED}Specify the encryption/decryption mode[OPTIONAL]:\n{RESET} "
            " - pure: Same as OTP but no encoding or authenthication feautures allowing you to use pure binary\n"
            f"  - OTP: Standard base64 encoded output.{RED}[RECOMMENDED]{RESET}\n"
            f"  - personal: Use your own password; Uses extremely secure methods. DEFAULT FOR ENCRYPTION {RED}[RECOMMENDED]{RESET}\n"
            f"  - auto: Automatically detect the mode during decryption {GREEN}(default){RESET}."
        )
    )
    parser.add_argument(
        "-f", "--file",
        type=str,
        metavar="<FILE>",
        help="Specify an input file for encryption or decryption."
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        metavar="<FILE>",
        help="Specify the output file for encryption or decryption."
    )

    argcomplete.autocomplete(parser)
    args = parser.parse_args()

    if args.encrypt:
        # --- Encryption Flow ---
        input_text = ""
        if args.file:
            try:
                with open(args.file, 'r') as f:
                    input_text = f.read()
            except FileNotFoundError:
                parser.error(f"Input file not found: {args.file}")
        elif isinstance(args.encrypt, str):
            input_text = args.encrypt
        else:
            parser.error("No input provided for encryption. Use -e <text> or -f <file>.")

        encryptedMsg = "Encryption Failed"
        Pass = "Encryption Failed"
        
        mode = args.mode
        if mode == "auto":
            mode = "personal" # Default to OTP for encryption

        if mode == "OTP":
            encryptedMsgandPass = encryptWithMode(input_text, "OTP")
            encryptedMsg = str(encryptedMsgandPass[0])
            Pass = str(encryptedMsgandPass[1])
            encryptedMsg = base64.b64encode(encryptedMsg.encode('latin-1')).decode('utf-8')
        elif mode == "pure":
            encryptedMsgandPass = encryptWithMode(input_text, "pure")
            encryptedMsg = repr(encryptedMsgandPass[0])
            Pass = repr(encryptedMsgandPass[1])
        elif mode == "personal":
            Pass = getpass()
            encryptedMsg = encode_base64(encryptCustomPass(input_text, Pass)) + "<PERSONAL>"
            Pass = r'---\HIDDEN/---'
        
        if args.output:
            try:
                with open(args.output, 'w') as f:
                    f.write(encryptedMsg)
                print(f"{GREEN}Encrypted message written to {args.output}{RESET}")
                if mode != 'personal':
                     # also write password to a file
                    pass_file = os.path.splitext(args.output)[0] + ".pass"
                    with open(pass_file, 'w') as f:
                        f.write(Pass)
                    print(f"{GREEN}Password written to {pass_file}{RESET}")

            except Exception as e:
                parser.error(f"Could not write to output file: {e}")
        else:
            print("encrypted:", encryptedMsg)
            print("Password:", Pass)

    elif args.decrypt:
        # --- Decryption Flow ---
        input_cipher = ""
        if args.file:
            try:
                with open(args.file, 'r') as f:
                    input_cipher = f.read().strip()
            except FileNotFoundError:
                parser.error(f"Input file not found: {args.file}")
        elif isinstance(args.decrypt, str):
            input_cipher = args.decrypt
        else:
            parser.error("No input provided for decryption. Use -d <cipher> or -f <file>.")

        Decrypted = "decryption failed"
        mode = args.mode

        if mode == "auto":
            if "<PERSONAL>" in input_cipher:
                mode = "personal"
            elif is_base64(input_cipher):
                mode = "OTP"
            else:
                mode = "pure"
            print(f"Detected {mode} mode")

        Password = ""
        if mode == "personal":
            Password = getpass("Enter password: ")
            input_cipher = input_cipher.removesuffix("<PERSONAL>")
        elif mode in ["OTP", "pure"]:
             # Try to read password from file or ask user
            pass_file = ""
            if args.file:
                pass_file = os.path.splitext(args.file)[0] + ".pass"
            
            try:
                with open(pass_file, 'r') as f:
                    Password = f.read()
                print(f"Read password from {pass_file}")
            except (FileNotFoundError, IOError):
                 Password = getpass("Enter password: ")


        if mode == "OTP":
            try:
                UsrInputStr2Decrypt = base64.b64decode(input_cipher).decode('latin-1')
                Decrypted = decryptAutoGenandPass(UsrInputStr2Decrypt, Password)
            except Exception as e:
                parser.error(f"Decryption Error: {e}")
        elif mode == "pure":
            UsrInputStr2Decrypt = decode_escape_sequences(input_cipher)
            Decrypted = decryptAutoGenandPass(UsrInputStr2Decrypt, Password)
        elif mode == "personal":
            UsrInputStr2Decrypt = decode_base64(input_cipher)
            Decrypted = decryptCustomPass(UsrInputStr2Decrypt, Password)

        if args.output:
            try:
                with open(args.output, 'w') as f:
                    f.write(Decrypted)
                print(f"{GREEN}Decrypted message written to {args.output}{RESET}")
            except Exception as e:
                parser.error(f"Could not write to output file: {e}")
        else:
            print(f"\nDecrypted message is:\n{RED}{Decrypted}{RESET}")

    else:
        parser.print_help()



if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('Interrupted')
        try:
            sys.exit(130)
        except SystemExit:
            os._exit(130)

