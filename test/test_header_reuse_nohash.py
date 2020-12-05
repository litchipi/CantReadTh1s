#!/usr/bin/env python3
#-*-encoding:utf-8*-

import os
import sys
import time
import random, string
import json
from cantreadth1s import CantReadThis

DEBUG=False#True
PASSWORD = "azeifjazeofjalzekfjamzlekfjmalkefjmqlkxd,vmqcvnx;,cvnbperjgoizejé"
DICT_TEST = {
        "metadata":{"toto":"tutu"},
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
    print("\n\n\n" + algo)
    crt = CantReadThis(password=PASSWORD, debug=DEBUG, compression_algorithm=algo)
    res = dict()
    try:
        res["metadata"] = crt.handle_dict(DICT_TEST["metadata"], nohash=True)
        assert (res is not None)
    except AssertionError:
        print("FAIL", res)
        return 1

    for key, val in DICT_TEST.items():
        if key == "metadata": continue
        try:
            res[key] = crt.handle_dict({key:val}, reuse_header=res["metadata"]["__crt__"], nohash=True)
            assert (res[key] is not None)
        except AssertionError:
            print("FAIL", key, res[key])
            return 1

    print("RES", res)
    print("\n")
    try:
        assert not any(["__crt__" in res[k].keys() for k in res.keys() if (k != "metadata")])
    except AssertionError:
        print("FAIL, got __crt__ in keys")
        return 1

    load = dict()
    crt2 = CantReadThis(password=PASSWORD, debug=DEBUG)
    
    header = dict.copy(res["metadata"]["__crt__"])
    try:
        load["metadata"] = crt2.handle_dict(res["metadata"])
        assert (load["metadata"] is not None)
    except AssertionError:
        print("FAIL", key, load["metadata"])
        return 1

    for key, val in res.items():
        if key == "metadata": continue
        try:
            load[key] = crt2.handle_dict(res[key], reuse_header=header)[key]
            assert (load[key] is not None)
        except AssertionError:
            print("FAIL", key, load[key])
            return 1

    print(load == DICT_TEST)
    print("Success")
    return 0

if __name__ == "__main__":
    os.system("clear")
    for algo in ["lzma", "bz2", "zlib", "lz4", "none"]:
        ret = main(algo)
        if ret != 0:
            sys.exit(ret)
