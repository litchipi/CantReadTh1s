#!/usr/bin/env python3
#-*-encoding:utf-8*-

import smaz
import random
import argparse
import sys
import os
import hashlib
import json
import getpass
import zlib
from Crypto.Cipher import AES
import argon2

VERSION = 0.2
TESTING = False

pad = lambda s: s + ((16 - len(s) % 16) * chr(16 - len(s) % 16)).encode()
unpad = lambda s : s[0:-s[-1]]

ARGON2_DEFAULT_CONF = {"t":128, "m":32, "p":8}

class CantReadThis:

    #AES encryption of a block of 16 bytes
    def encrypt_data(self, data, pwd):
        return AES.new(pwd).encrypt(pad(data))

    def decrypt_data(self, data, pwd):
        return unpad(AES.new(pwd).decrypt(data))

    
    #ZLib compression for data (fast & efficient binary compression)
    def compress_data(self, data):
        res = zlib.compress(data)
        return res

    def decompress_data(self, data):
        res = zlib.decompress(data)
        return res

    def compute_hash(self, data):
        return hashlib.sha256(data).digest()

    #Header compressed with smaz, light process for text compression
    def compress_text(self, data):
        return smaz.compress(data)

    def decompress_text(self, data):
        return smaz.decompress(data)



    def int_to_bytes(self, i):
        return int(i).to_bytes((i.bit_length()//8)+1, "big", signed=False)

    #Header format:
    #   header_length|smaz_compress({dict of header})
    def create_header(self, data, pwd, argon2_opt, info):
        if info is None: info = "Processed with CantReadThis v" + str(VERSION)
        h = self.compute_hash(data)
        header = {
                "l":len(data), #DATA LENGTH
                "h":h.hex(),  #DATA HASH
                "a":argon2_opt,
                "i":info.replace(" ", "_")
                }
        bin_data = self.compress_text(json.dumps(header).replace(" ", ""))
        if TESTING:
            print(len(json.dumps(header).replace(" ", "")), len(bin_data), 100*(len(json.dumps(header).replace(" ", ""))/len(bin_data)))
        res = self.int_to_bytes(len(bin_data)) + bytes("|".encode()) + bin_data
        return res

    #Test if we can extract data from the header
    def test_processed(self, data):
        return (self.extract_header(data)[0] is not None)

    def ask_password(self, prompt, opt=None):
        if TESTING:
            return self.compute_hash("tata".encode())
        else:
            if opt is None:
                opt = ARGON2_DEFAULT_CONF
            return argon2.argon2_hash("CantReadTh1s_Password", hashlib.sha256(getpass.getpass(prompt).encode()).digest(), t=opt["t"], m=opt["m"], p=opt["p"], buflen=32), opt

    def extract_header(self, data):
        try:
            datalen_bin = data.split("|".encode())[0]
            datalen = int.from_bytes(datalen_bin, "big", signed=False)
            header_bin = data[len(datalen_bin)+1:len(datalen_bin)+1+datalen]
            return json.loads(self.decompress_text(header_bin)), data.replace(data[:len(datalen_bin)+1+datalen], "".encode())
        except Exception as err:
            return None, data

    def header_check(self, data):
        header, data = self.extract_header(data)
        if header is None:
            return False, "Header cannot be extracted from file"
        data_hash = self.compute_hash(data).hex()
        if (data_hash != header["h"]):
            return False, "Wrong file hash"
        data_len = len(data)
        if (data_len != header["l"]):
            return False, "Wrong data length"
        return True, data, header

    def byte_to_measure(self, b, nprec=1):
        i = 0
        let = ["b", "K", "M", "G", "T", "P"]
        while b > 1024:
            b = b/1024
            i += 1
        return str(round(b, nprec)) + let[i]


    def read_processed_data(self, data):
        success, data, header = self.header_check(data)
        print("Information about the file:\n\t" + str(header["i"].replace("_", " ")))
        pwd, opt = self.ask_password("Enter password for data decryption: ", opt=header["a"])
        if not success: return False, msg

        pln_data = self.decrypt_data(data, pwd)
        try:
            dec_data = self.decompress_data(pln_data)
        except zlib.error:
            return False, "Bad password or corrupted backup"
        
        return True, dec_data

    def process_plaindata(self, data, fname, info):
        pwd, opt = self.ask_password("Enter password for data encryption: ")
        cmp_data = self.compress_data(data)
        enc_data = self.encrypt_data(cmp_data, pwd)
        data_head= self.create_header(enc_data, pwd, opt, info)
        with open(fname + ".cant_read_this", "wb") as f:
            f.write(data_head)
            f.write(enc_data)
        
        src_sz = os.path.getsize(fname)
        dst_sz = os.path.getsize(fname + ".cant_read_this")
        ratio = round((float(dst_sz)/src_sz)*100,2)

        print("\nStored securely\n\t" + fname + ".cant_read_this" + "\n\t" + self.byte_to_measure(src_sz) + " -> " + self.byte_to_measure(dst_sz))
        return True, None 

    def handle_file(self, fname, **kwargs):
        if not os.path.isfile(fname):
            return False, "File doesn't exist"
        with open(fname, "rb") as f:
            data = f.read()
        return self.handle_data(data, fname, **kwargs)

    def handle_data(self, data, fname, out=None, info=None, display=False):
        #PROCESSED FILE TO RECOVER
        if self.test_processed(data):
            res = self.read_processed_data(data)
            if out is not None:
                with open(out, "wb") as f:
                    f.write(res[1])
            if display and res[0]:
                self.display_data(res[1])
            return res

        # PLAINDATA FILE TO PROCESS
        else:
            return self.process_plaindata(data, fname, info)

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
        success, data = cr.handle_file(args.fname, out=args.outfile, info=args.info, display=(args.outfile is None))
        if not success:
            print("Failed:\n\t" + data)

if __name__ == "__main__":
    main()
