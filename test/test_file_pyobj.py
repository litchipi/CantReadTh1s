#!/usr/bin/env python3
#-*-encoding:utf-8*-

import random, string
from cantreadth1s import CantReadThis
import os

DEBUG=False
PASSWORD = "lknzealfkalmzekjfamejfamlzejfmalk"

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

    crt = CantReadThis(password=PASSWORD, debug=DEBUG, return_data=True, compression_algorithm=algo)
    print("\n[*] Creating encrypted file")
    success, result = crt.handle_file("testfile")
    if not success:
        print("FAIL", outf)
        return 1
    print(result)
    for a, b, c in os.walk(os.path.abspath(os.path.curdir)):
        print(a, b, c)
    with open("testfile.crt", "wb") as f:
        f.write(result)

    print("\n[*] Loading from encrypted file")
    crt2 = CantReadThis(password=PASSWORD, debug=DEBUG, return_data=True)
    success, loaded = crt2.handle_file("testfile.crt")
    if not success:
        print("FAIL", loaded)
        return 1

    print("\n[*] Results")
    loaded = loaded.decode()
    print("\t" + plain_data + " == " + loaded + " ? \t-> " + str(plain_data == loaded))

    os.remove("testfile")
    os.remove("testfile.crt")

if __name__ == "__main__":
    os.system("clear")
    for algo in ["lzma", "bz2", "zlib", "lz4", "none"]:
        main(algo)
