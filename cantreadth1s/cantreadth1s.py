#!/usr/bin/env python3
#-*-encoding:utf-8*-

import io
import smaz
import random
import argparse
import sys
import os
import hashlib
import json
import getpass
import bz2
from Crypto.Cipher import AES
import argon2
import multiprocessing as mproc

VERSION = 0.3
TESTING = False

pad = lambda s: s + ((16 - len(s) % 16) * chr(16 - len(s) % 16)).encode()
unpad = lambda s : s[0:-s[-1]]

ARGON2_DEFAULT_CONF = {"t":128, "m":32, "p":8}

def open_compressed_file(*args, **kwargs):
    return bz2.open(*args, **kwargs)

class CantReadThis:

    def __init__(self):
        self.ncpu = mproc.cpu_count()
        self.tmp_file_data = {"filesize":None}
        self.rsize = (50*1024*1024)

    #AES encryption of a block of 16 bytes
    def encrypt_data(self, data, pwd):
        return AES.new(pwd).encrypt(pad(data))

    def decrypt_data(self, data, pwd):
        return unpad(AES.new(pwd).decrypt(data))

    #Header compressed with smaz, light process for text compression
    def compress_text(self, data):
        return smaz.compress(data)

    def decompress_text(self, data):
        return smaz.decompress(data)

    def int_to_bytes(self, i):
        return int(i).to_bytes((i.bit_length()//8)+1, "big", signed=False)

    #Header format:
    #   header_length|smaz_compress({dict of header})
    def create_header(self, datahash, pwd, argon2_opt, info):
        if info is None: info = "Processed with CantReadThis v" + str(VERSION)
        header = {
                "l":self.tmp_file_data["filesize"],
                "h":datahash,
                "a":argon2_opt,
                "i":info.replace(" ", "_")
                }
        bin_head = self.compress_text(json.dumps(header).replace(" ", ""))
        if TESTING:
            print(len(json.dumps(header).replace(" ", "")), len(bin_head), 100*(len(json.dumps(header).replace(" ", ""))/len(bin_head)))
        res = self.int_to_bytes(len(bin_head)) + self.int_to_bytes(0) + bin_head
        return res

    #Test if we can extract data from the header
    def test_processed(self, dataf):
        return (self.extract_header(dataf)[0] is not None)

    def ask_password(self, prompt, opt=None):
        if TESTING:
            return self.compute_hash("tata".encode())
        else:
            if opt is None:
                opt = ARGON2_DEFAULT_CONF
            return argon2.argon2_hash("CantReadTh1s_Password", hashlib.sha256(getpass.getpass(prompt).encode()).digest(), t=opt["t"], m=opt["m"], p=opt["p"], buflen=32), opt

    def extract_header(self, dataf):
        n = 0
        dread = None
        while (dread is None) or (dread != self.int_to_bytes(0)):
            help(dataf)
            dread = dataf.read(size=1)
            print("DBG> Byte read: " + dread.hex())
            n += 1
        print("DBG> Headerlen byte end: " + str(n))
        dataf.seek(0)
        headerlen_bin = dataf.read(size=(n-1))
        print("DBG> Headerlen byte: " + headerlen_bin.hex())
        headerlen = int.from_bytes(headerlen_bin, "big", signed=False)
        print("DBG> Headerlen: " + str(headerlen))
        dataf.seek(len(headerlen_bin)+1)
        header_bin = dataf.read(headerlen)
        print("DBG> Headerbin: " + header_bin.hex())
        return json.loads(self.decompress_text(header_bin)), len(headerlen_bin)+1+headerlen

    def compute_hash(self, dataf):
        n = self.rsize
        h = hashlib.sha256(dataf.read(self.rsize))
        while (n < self.tmp_file_data["filesize"]):
            h.update(dataf.read(self.rsize))
        return h.hexdigest()

    def header_check(self, dataf):
        header, data_start = self.extract_header(dataf)
        if header is None:
            return False, "Header cannot be extracted from file"
        dataf.seek(data_start)
        data_hash = self.compute_hash(dataf)
        if (data_hash != header["h"]):
            return False, "Wrong file hash"
        data_len = (self.tmp_file_data["filesize"] - data_start)
        if (data_len != header["l"]):
            return False, "Wrong data length"
        return True, data_start, header

    def byte_to_measure(self, b, nprec=1):
        i = 0
        let = ["b", "K", "M", "G", "T", "P"]
        while b > 1024:
            b = b/1024
            i += 1
        return str(round(b, nprec)) + let[i]

    def load_processed_data(self, dataf, data_start, pwd, orig_rsize, fout):
        with mproc.Pool(self.ncpu) as pool:
            n = 0
            fct = lambda d: self.decrypt_data(d, pwd)
            dataf.seek(data_start)
            while n < self.tmp_file_data["filesize"]:
                data_chunks = list()
                for i in range(self.ncpu):
                    data_chunks.append(dataf.read(self.rsize))
                    n += self.rsize
                for r in pool.map(fct, data_chunks):
                    fout.write(r)

    def load_data(self, dataf, fout, display=False):
        success, data_start, header = self.header_check(dataf)
        if display:
            print("Information about the file:\n\t" + str(header["i"].replace("_", " ")))
        pwd, opt = self.ask_password("Enter password for data decryption: ", opt=header["a"])
        if not success: return False, msg
        self.load_processed_data(dataf, data_start, pwd, opt["s"], fout)
        return True, fout

    def process_data(self, dataf, fout, pwd):
        with mproc.Pool(self.ncpu) as pool:
            n = 0
            fct = lambda d: self.encrypt_data(d, pwd)
            dataf.seek(0)
            while n < self.tmp_file_data["filesize"]:
                data_chunks = list()
                for i in range(self.ncpu):
                    data_chunks.append((dataf.read(self.rsize), pwd))
                    n += self.rsize
                for r in pool.starmap(self.encrypt_data, data_chunks):
                    fout.write(r)


    def process_plaindata(self, dataf, fout, info=None, display=False, **kwargs):
        pwd, opt = self.ask_password("Enter password for data encryption: ")
        datahash = self.compute_hash(dataf)
        data_head= self.create_header(datahash, pwd, opt, info)
        
        fout.write(data_head)
        self.process_data(dataf, fout, pwd)
        fout.close()
        return True

    def handle_file(self, fname, rsize=None, ret_data=False, **kwargs):
        if not os.path.isfile(fname):
            return False, "File doesn't exist"

        self.tmp_file_data["filesize"] = os.path.getsize(fname)
        if rsize is not None:
            self.rsize = rsize
        self.rsize = self.rsize-(self.rsize%16)

        with open(fname, "rb") as f:
            help(f)
            processed = self.test_processed(f)

        if processed:
            with open_compressed_file(fname, "rb") as f:
                return self.handle_processed_data(f, **kwargs)
        else:
            with open(fname, "rb") as dataf:
                with open_compressed_file(fname + ".cant_read_this", "wb") as fout:
                    success = self.process_plaindata(dataf, fout, **kwargs)
            if success and kwargs["display"]:
                src_sz = os.path.getsize(fname)
                dst_sz = os.path.getsize(fname + ".cant_read_this")
                ratio = round((float(dst_sz)/src_sz)*100,2)
                print("\nStored securely\n\t" + fname + ".cant_read_this" + "\n\t" + self.byte_to_measure(src_sz) + " -> " + self.byte_to_measure(dst_sz))
            if ret_data:
                with open_compressed_file(fname + ".cant_read_this", "rb") as f:
                    return sucess, f.read()

    def handle_processed_data(dataf, out=None, display=False, ret_data=False, **kwargs):
        if out is not None:
            res = open(out, "w+b")
        elif display:
            res = io.BufferedRandom()

        try:
            success, res = self.load_data(dataf, res, display=display)
            if not success:
                return False

            if display:
                res.seek(0)
                self.display_data(res.read())

            if ret_data:
                res.seek(0)
                ret = res.read()

        finally:
            res.close()

        if ret_data:
            return ret
        return True

    def display_data(self, data):
        try:
            s = str(data.decode()) + "\n"
            os.system("clear")
            sys.stdout.write(s)
        except:
            sys.stdout.write(str(data) + "\n")
            sys.stdout.write(type(data).__name__ + "\n")
        sys.stdout.flush()



###############################################################################
def test_unit(teststr, dispall=True):
    print("Not implemented")
    return
    import time
    cr = CantReadThis()
    print("\n"*2)
    if dispall:
        print("Testing with data: " + teststr)
    else:
        print("Testing with data: " + teststr[:10] + "...")
    print("Data length: " + str(len(teststr)))
    print("Hash of data: " + cr.compute_hash(teststr.encode()).hex())
    with open("testfile", "w") as fichier:
        fichier.write(teststr)

    print("\nPROCESSING" + "-" * 50)
    success, proc_res = cr.handle_file("testfile")
    if not success:
        print("Error while processing the file:\n\t" + proc_res)
        return
    if dispall:
        print("Result: " + str(proc_res))
    else:
        print("Result: " + str(proc_res[:10]) + "...")
    print("Data length: " + str(len(proc_res)))
    print("Hash of data: " + cr.compute_hash(proc_res).hex())

    print("\nRECOVERING" + "-" *50)
    t = time.time()
    success, loaded = cr.handle_file("testfile.cant_read_this")
    dt = time.time()-t
    loaded = loaded.decode('utf-8')
    if not success:
        print("Error while recovering the file:\n\t" + loaded)
        return
    if dispall:
        print("Result: " + loaded)
    else:
        print("Result: " + loaded[:10] + "...")
    print("Data length: " + str(len(loaded)))
    print("Hash of data: " + cr.compute_hash(loaded.encode()).hex())

    print("Ratio: {}/{} = {}%".format(len(proc_res), len(loaded), round(100*(float(len(proc_res))/len(loaded)), 2)))
    print("Speed: ")
    print("\t{}  bytes/s".format(len(loaded)/dt))
    print("\t{} Kib/s".format((len(loaded)/1024)/dt))
    print("\t{} Mib/s".format((len(loaded)/(1024*1024))/dt))

def test():
    global TESTING
    TESTING = True

    test_unit("Super secret password")
    alphabet_n = [chr(i) for i in range(ord("A"), ord("Z"))] + [chr(i) for i in range(ord("a"), ord("z"))] + [chr(i) for i in range(ord("0"), ord("9"))]
    for n in range(2, 13):
        test_unit("".join([random.choice(alphabet_n) for i in range(10**n)]), dispall=False)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('fname', metavar='filename', type=str, help="The file you want to process/recover")
    parser.add_argument('--outfile', '-o', type=str, help='Where to save the recovered data (if nothing is passed, will print it in stdout)')
    parser.add_argument('--testing', '-t', action="store_true", help="Perform tests on the system if set")
    parser.add_argument('--info', '-i', type=str, help='Information about the file, its content or an indication of the password')

    cr = CantReadThis()
    args = parser.parse_args()
    if args.testing:
        test()
    else:
        cr.handle_file(args.fname, out=args.outfile, info=args.info, display=(args.outfile is None))

if __name__ == "__main__":
    main()
