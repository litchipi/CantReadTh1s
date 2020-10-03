#!/usr/bin/env python3
#-*-encoding:utf-8*-

import os
import sys
import time
import random, string
import json
from cantreadth1s import CantReadThis

DEBUG=False
ALGORITHM = "lz4"
PASSWORD = "azeifjazeofjalzekfjamzlekfjmalkefjmqlkxd,vmqcvnx;,cvnbperjgoizejé"
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

def main(sec_level):
    print("\n\n\n" + str(sec_level))
    print(str(DICT_TEST)[:80])
    crt = CantReadThis(password=PASSWORD, debug=DEBUG, compression_algorithm=ALGORITHM, security_level=sec_level)
    try:
        res = crt.handle_dict(DICT_TEST)
    except AssertionError:
        print("FAIL", res)
        return 1
    res["toto"] = "tata"
    print("")
    print(list(res.keys()))
    print(str(res["__crt__"]))
    print(len(json.dumps(DICT_TEST)), " -> ", len(res["__data__"]))
    print("")
    crt2 = CantReadThis(password=PASSWORD, debug=DEBUG)
    try:
        load = crt2.handle_dict(res)
    except AssertionError:
        print("FAIL", load)
        return 1
    print(load)
    print("Success")
    return 0

if __name__ == "__main__":
    os.system("clear")
    for sec in range(1, 100, 5):
        ret = main(sec)
        if ret != 0:
            sys.exit(ret)
