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
    defaultsfn =  ["Encrypted.txt","Password.txt","Decrypted.txt"]
    parser = argparse.ArgumentParser(
        description="A command-line tool for XOR encryption and decryption.",
        #modeter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=40)
        formatter_class=argparse.RawTextHelpFormatter
        )
    parser.add_argument(
        "-e", "--encrypt",
        type=str,
        default=None,
        metavar="<TEXT>",
        help="Encrypt the given text. Use with -f to specify the output mode."
    )
    parser.add_argument(
        "-d", "--decrypt",
        nargs='?',
        type=str,
        default=None,
        metavar="<CIPHER>",
        help="Decrypt the given ciphertext. Use with -f to specify the input mode."
    )
    parser.add_argument(
        "-m", "--mode",
        choices=['pure', 'OTP', 'personal', "auto"],
        default="auto",
        help=(
            f"{RED}Specify the encryption/decryption mode[OPTIONAL]:\n{RESET} "
            " - pure: Same as OTP but no encoding or authenthication feautures allowing you to use pure binary\n"
            "  - OTP: Standard base64 encoded output. DEFAULT[RECOMMENDED]\n"
            "  - personal: Use your own password [RECOMMENDED]\n"
            f"  - auto: Automatically detect the mode during decryption {GREEN}(default){RESET}."
        )
    )

    parser.add_argument(
        "-f", "--file",
        nargs='*',
        metavar=('FILENAMES[Encrypted, Password, Decrypted]'),
        help="EncryptedMessageFilename, PasswordFilename, DecryptedMessageFilename"
    )

    argcomplete.autocomplete(parser)
    args = parser.parse_args()
    print(f"DEBUG: args.mode is {args.mode}")

    #if encrypt mode:
    if args.encrypt:
        autoState = False
        encryptedMsg = "Encryption Failed"
        Pass = "Encryption Failed"
        if args.mode == "auto": autoState = True
        if args.mode == "auto" or args.mode == "OTP":
            UsrInputStr2Encrypt = args.encrypt
            encryptedMsgandPass = encryptAutoGenandPass(UsrInputStr2Encrypt)
            encryptedMsg = str(encryptedMsgandPass[0])
            Pass = str(encryptedMsgandPass[1])
            encryptedMsg = base64.b64encode(encryptedMsg.encode('latin-1')).decode('utf-8') 
        if args.mode == "pure":
            UsrInputStr2Encrypt = args.encrypt
            encryptedMsgandPass = encryptAutoGenandPass(UsrInputStr2Encrypt)
            encryptedMsg = repr(encryptedMsgandPass[0])
            Pass = repr(encryptedMsgandPass[1])
        if args.mode == "personal":
            UsrInputStr2Encrypt = args.encrypt
            Pass = getpass()
            encryptedMsg = encode_base64(encryptCustomPass(UsrInputStr2Encrypt, Pass)) + "<PERSONAL>"
            Pass = r'---\HIDDEN/---'

        print("encrypted:", encryptedMsg)
        print("Password:", Pass)
        if autoState: print(f"\n{RED}mode not specified, defaulted to OTP mode{RESET}")
        if args.mode == "pure": print(f"{RED}Warning: Using pure mode is not very supported as it may result in truncation of text. Should work fine most of the time.{RESET}")

    #if decrypt mode
    elif args.decrypt is not None or args.file is not None:
        Decrypted = "decryption failed"
        autoState = False
        AllowNormal = True
        FileUsageState = False
        if True:
            if args.file is None and args.decrypt is None:
                parser.error("No arguement for decryption given and no filename was specified")
            if args.file is not None and args.decrypt is not None:
                parser.error("When -f is specified, -d must have no arguements")
            if args.file is not None:
                if len(args.file) == 0:
                    pass
                if len(args.file) > 3 and len(args.file) != 0:
                    parser.error("-f only accepts 3 arguements at most")
                args.file = args.file + defaultsfn[len(args.file):]
                AllowNormal = False
                FileUsageState = True
                try:
                    with open(args.file[0], 'r') as f:
                        args.decrypt = f.read().strip() # it took so long to figure out  but stripping is required for auto detection to work as expected
                    if args.mode != "personal":
                        with open(args.file[1], 'r') as f:
                            Password = f.read()
                    elif args.mode == "personal":
                        AllowNormal = True
                except FileNotFoundError:
                    print("Error: The file was not found.(Encrypted File or Password File)")
                except Exception as e:
                    print(f"An error occurred: {e}")

            if AllowNormal or args.mode == "personal":
                print("false")
                print(args.mode)
                Password = getpass()
            

        if args.mode == "auto":
            autoState = True
            if "<PERSONAL>" in args.decrypt:
                args.decrypt = args.decrypt.removesuffix("<PERSONAL>")
                print("Detected personal mode")
                args.mode = "personal"
            elif is_base64(args.decrypt):
                args.mode = "OTP"
                print("Detected OTP mode")
            else:
                args.mode = "pure"
                print("Detected pure mode")
        if args.mode == "OTP":
            try:
                UsrInputStr2Decrypt = base64.b64decode(args.decrypt).decode('latin-1')
            except Exception as e:
                print(f"Decryption Error: Are you using the right mode? DEBUG:{e}")
                exit()
            UsrInputPswd = Password
            Decrypted = decryptAutoGenandPass(UsrInputStr2Decrypt, UsrInputPswd)
        if args.mode == "pure":
            UsrInputStr2Decrypt = decode_escape_sequences(args.decrypt) #convert repr to ascii; may result in obfuscation
            UsrInputPswd = Password
            Decrypted = decryptAutoGenandPass(UsrInputStr2Decrypt, UsrInputPswd)
        if args.mode == "personal":
           UsrInputStr2Decrypt = decode_base64(args.decrypt)
           UsrInputPswd = Password
           Decrypted = decryptCustomPass(UsrInputStr2Decrypt, UsrInputPswd)
        if args.file is None:
            print(f"\nDecrypted message is:\n{RED}{Decrypted}{RESET}")
            if autoState: print(f"\n{RED}{args.mode} mode was detected. If output was unexpected, try using -f to choose decryption method manually.")
            if args.mode == "pure": print("\nNote: Due to the nature of pure mode, authenticity of message cannot be guaranteed.")
        if args.file is not None:
            with open(args.file[2], 'w') as f:
                f.write(Decrypted)
        if FileUsageState:
            print(f"Decrypted output has been transferred to {args.file[2]}")
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

