from xorkey.core import *
from xorkey.utils import *
import argparse
def main():
    parser = argparse.ArgumentParser(description="A encryption software utilising XOR, pretty much unbreakable")
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
            help="autogen:portable; personal:this app only; bin:personal but in binary; autodetect:if you're confused then probably use this unless there is an error"
             )
    args = parser.parse_args()
    if args.encrypt:
        result = "yay"
        print(result)
main()
