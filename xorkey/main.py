from xorkey.core import *
from xorkey.utils import *
import argparse
import sys
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
            choices=['autogen', 'bin', 'personal',"autodetect"],
            default="autodetect",
            help=("   autogen: portable;\n"
            "  personal: this app only;\n"
            "       bin: personal but in binary;\n"
            "autodetect: if you're confused then probably use this unless there is an error"
                  )
            )
    args = parser.parse_args()
    if args.encrypt:
        UsrInputStr2Encrypt = args.encrypt 
        encryptedMsgandPass = encryptAutoGenandPass(UsrInputStr2Encrypt)
        encryptedMsg = str(encryptedMsgandPass[0])  # KEEP THIS LINE
        Pass = str(encryptedMsgandPass[1])          # KEEP THIS LINE
        
        # Encode to base64
        encryptedMsgBase64 = base64.b64encode(encryptedMsg.encode('latin-1')).decode('utf-8')
        
        print("encrypted:", encryptedMsgBase64)
        print("Password:", repr(Pass))
    if args.decrypt:
        UsrInputStr2Decrypt = base64.b64decode(args.decrypt).decode('latin-1')
        UsrInputPswd = input("Password?\n")
        print(decryptAutoGenandPass(UsrInputStr2Decrypt, UsrInputPswd)) 
    elif len(sys.argv) == 1:
        print("No arguement eprovided; Use -h to see manual")
if __name__ == "__main__":
    main()
