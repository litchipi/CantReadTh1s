#!/usr/bin/env python3
#-*-encoding:utf-8*-

import os
import time
import random, string
import json
from cantreadth1s import CantReadThis

PASSWORD = "azeifjazeofjalzekfjamzlekfjmalkefjmqlkxd,vmqcvnx;,cvnbperjgoizejé"
DICT_TEST = {
        "key_list_int": [1, 3, 5, 7, 9],
        "key_list_str": ["tata", "toto", "tointoin", "tutu"],
        "key_list_float": [0.234523456, 0.00001234, 0.65432143],
        "key_dict": {
            "key0": "data0",
            "key1": 234,
            "key2": [234, 54, 645, 234],
            "key3": {
                "key": "val"
                }
            },
        }

COMPRESSION_ALGORITHMS_AVAILABLE = ["lzma", "bz2", "zlib", "lz4", "none"]#"brotli", "none"]

def random_word():
    return "".join(random.sample(string.ascii_letters + string.digits, random.randrange(5, 40)))

def find_best_comp(nsamples=100):
    benchmark_res = dict()
    ndone = 0
    while ndone < nsamples:
        d = dict()
        for key in ["key" + str(i) for i in range(500)]:
            if random.random() < 0.1:
                d[key] = [random_word() for i in range(random.randrange(5, 20))]
            elif random.random() < 0.05:
                d[key] = {random_word():[random_word() for i in range(random.randrange(5, 20))] for n in range(random.randrange(2, 30))}
            elif random.random() < 0.45:
                d[key] = random.randrange(1, 1234123)
            else:
                d[key] = random_word()
        for comp in COMPRESSION_ALGORITHMS_AVAILABLE:
            t = time.time()
            nres, nini, ratio = test_params("randomgenerateddict", dict.copy(d), comp=comp, verbose=False)
            if comp not in benchmark_res:
                benchmark_res[comp] = {k:(0, 0) for k in ["time", "ratio"]}
            dt = time.time()-t
            benchmark_res[comp]["time"] = (float((benchmark_res[comp]["time"][0]*benchmark_res[comp]["time"][1]) + dt)/(benchmark_res[comp]["time"][1] + 1), benchmark_res[comp]["time"][1] +1)
            benchmark_res[comp]["ratio"] = (float((benchmark_res[comp]["ratio"][0]*benchmark_res[comp]["ratio"][1]) + ratio)/(benchmark_res[comp]["ratio"][1] + 1), benchmark_res[comp]["ratio"][1]+1)
            benchmark_res[comp]["score"] = (((1/(1+benchmark_res[comp]["time"][0])) * (1/(benchmark_res[comp]["ratio"][0]+1))), benchmark_res[comp]["time"][1])
        os.system("clear")
        ndone += 1
        print(str(ndone).rjust(len(str(nsamples))) + "/" + str(nsamples) + " samples done (" + str(round((float(ndone)/nsamples)*100, 2)).rjust(5) + "%)")
        for comp, data in benchmark_res.items():
            print(comp)
            for metric, value in data.items():
                print("\t{}\t{}".format(metric, value[0]))
        best = max([(comp, benchmark_res[comp]["score"][0]) for comp in benchmark_res.keys()], key=lambda x: x[1])
        print("Best: " + best[0])
        time.sleep(0.025)

def test_params(pwd, data, comp="zlib", verbose=True):
    crt = CantReadThis(pwd=PASSWORD, params={"string_compression_algorithm":comp})

    success, res = crt.handle_dict(data)
    crt2 = CantReadThis(pwd=PASSWORD)#, params={"string_compression_algorithm":comp})
    success, loaded = crt2.handle_dict(res)
    if verbose:
        print("")
        print(data)
        print(res)
        print(loaded == data)

    nres = len(json.dumps(res))
    nini = len(json.dumps(data))
    if verbose:
        print(nres, nini, str(round(float(nres)/nini, 3)) + "x")
        print("\n\n\n\n")
    return nres, nini, round(float(nres)/nini, 3)

test_params(PASSWORD, DICT_TEST)
test_params("testemptydict", {})
find_best_comp()
