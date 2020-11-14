#!/usr/bin/env python3
#-*-encoding:utf-8*-

import random, string
from cantreadth1s import CantReadThis, BadPasswordException
import os

DEBUG=True
GOOD_PASSWORD = "lknzealfkalmzekjfamejfamlzejfmalk"

def main(algo):
    print("\n\n\n" + algo)
    plain_data = "Hello world"
    try:
        os.remove("testfile")
    except:
        pass
    try:
        os.remove("testfile.crt")
    except:
        pass
    with open("testfile", "w") as f:
        f.write(plain_data)

    crt = CantReadThis(password=GOOD_PASSWORD, debug=DEBUG, return_data=True, compression_algorithm=algo)
    print("\n[*] Creating encrypted file")
    success, result = crt.handle_file("testfile")
    if not success:
        print("FAIL", outf)
        return 1
    print("OK")
    with open("testfile.crt", "wb") as f:
        f.write(result)

    print("\n[*] Loading from encrypted file")
    crt2 = CantReadThis(debug=DEBUG, return_data=True)
    success, loaded = crt2.handle_file("testfile.crt")
    if success:
        print("FAIL")
        return 1
    print("Success: ", loaded)

    os.remove("testfile")
    os.remove("testfile.crt")

if __name__ == "__main__":
    os.system("clear")
    for algo in ["lzma", "bz2", "zlib", "lz4", "none"]:
        main(algo)
