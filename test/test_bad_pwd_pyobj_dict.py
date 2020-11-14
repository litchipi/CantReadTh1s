#!/usr/bin/env python3
#-*-encoding:utf-8*-

import os
import sys
import time
import random, string
import json
from cantreadth1s import CantReadThis, BadPasswordException

DEBUG=False#True
GOOD_PASSWORD = "azeifjazeofjalzekfjamzlekfjmalkefjmqlkxd,vmqcvnx;,cvnbperjgoizejé"
BAD_PASSWORD = "lakefjlkazejflkazjel"

DICT_TEST = {
        "key_list_int": [1, 3, 5, 7, 9],
        "key_list_str": ["tata", "toto", "tointoin", "tutu"],
        "key_list_float": [0.234523456, 0.00001234, 0.65432143],
        "key_list_int2": [1, 3, 5, 7, 9],
        "key_list_str2": ["tata", "toto", "tointoin", "tutu"],
        "key_list_float2": [0.234523456, 0.00001234, 0.65432143],

        "key_dict": {
            "key0": "data0",
            "key1": 234,
            "key2": [234, 54, 645, 234],
            "key3": {
                "key": "val"
                }
            },
        }

def main(algo):
    print("\n\n" + algo)
    crt = CantReadThis(password=GOOD_PASSWORD, debug=DEBUG, compression_algorithm=algo)
    try:
        res = crt.handle_dict(DICT_TEST)
        assert (res is not None)
    except AssertionError:
        print("FAIL", res)
        return 1
    res["toto"] = "tata"
    crt2 = CantReadThis(password=BAD_PASSWORD, debug=DEBUG)
    try:
        load = crt2.handle_dict(res)
        print(load)
        print("FAIL")
        return 1
    except BadPasswordException:
        print("Success")
    return 0

if __name__ == "__main__":
    os.system("clear")
    for algo in ["lzma", "bz2", "zlib", "lz4", "none"]:
        ret = main(algo)
        if ret != 0:
            sys.exit(ret)
