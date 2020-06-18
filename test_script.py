#!/usr/bin/env python3
#-*-encoding:utf-8*-

import random, string
from cantreadth1s import CantReadThis
import os

plain_data = "Hello world"
with open("test", "w") as f:
    f.write(plain_data)

crt = CantReadThis()
print("\n[*] Creating encrypted file")
crt.handle_file("test")

print("\n[*] Loading from encrypted file")
crt2 = CantReadThis()
success, loaded = crt2.handle_file("test.cant_read_this")

print("\n[*] Results")
if success:
    loaded = loaded.decode()
    print("\t" + plain_data + " == " + loaded + " ? \t-> " + str(plain_data == loaded))
else:
    print("Failed")
