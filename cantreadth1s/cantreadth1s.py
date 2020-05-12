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

TESTING = False

pad = lambda s: s + ((16 - len(s) % 16) * chr(16 - len(s) % 16)).encode()
unpad = lambda s : s[0:-s[-1]]

class CantReadThis:
    def encrypt_data(self, data, pwd):
        return AES.new(pwd).encrypt(pad(data))

    def decrypt_data(self, data, pwd):
        return unpad(AES.new(pwd).decrypt(data))

    def compress_data(self, data):
        res = zlib.compress(data)
        return res

    def decompress_data(self, data):
        res = zlib.decompress(data)
        return res

    def compute_hash(self, data):
        return hashlib.sha256(data).digest()

    def compress_header(self, data):
        return smaz.compress(data)

    def decompress_header(self, data):
        return smaz.decompress(data)

    def int_to_bytes(self, i):
        return int(i).to_bytes((i.bit_length()//8)+1, "big", signed=False)

    def create_header(self, data, pwd):
        h = self.compute_hash(data)
        header = {
                "l":len(data), #DATA LENGTH
                "h":h.hex()  #DATA HASH
                }
        bin_data = self.compress_header(json.dumps(header).replace(" ", ""))
        if TESTING:
            print(len(json.dumps(header).replace(" ", "")), len(bin_data), 100*(len(json.dumps(header).replace(" ", ""))/len(bin_data)))
        return self.int_to_bytes(len(bin_data)) + bytes("|".encode()) + bin_data

    def test_processed(self, data):
        return (self.extract_header(data)[0] is not None)

    def ask_password(self, prompt):
        if TESTING:
            return self.compute_hash("tata".encode())
        else:
            return self.compute_hash(self.compute_hash(self.compute_hash(self.compute_hash(getpass.getpass(prompt).encode()))))

    def extract_header(self, data):
        try:
            datalen_bin = data.split("|".encode())[0]
            datalen = int.from_bytes(datalen_bin, "big", signed=False)
            header_bin = data[len(datalen_bin)+1:len(datalen_bin)+1+datalen]
            return json.loads(self.decompress_header(header_bin)), data.replace(data[:len(datalen_bin)+1+datalen], "".encode())
        except Exception as err:
            return None, data

    def header_check(self, data, pwd):
        header, data = self.extract_header(data)
        if header is None:
            return False, "Header cannot be extracted from file"
        data_hash = self.compute_hash(data).hex()
        if (data_hash != header["h"]):
            return False, "Wrong file hash"
        data_len = len(data)
        if (data_len != header["l"]):
            return False, "Wrong data length"
        return True, data

    def read_processed_data(self, data):
        pwd = self.ask_password("Enter password for data decryption: ")
        success, data = self.header_check(data, pwd)
        if not success: return False, msg

        pln_data = self.decrypt_data(data, pwd)
        dec_data = self.decompress_data(pln_data)
        return True, dec_data

    def process_plaindata(self, data, fname):
        pwd = self.ask_password("Enter password for data encryption: ")
        cmp_data = self.compress_data(data)
        enc_data = self.encrypt_data(cmp_data, pwd)
        data_head= self.create_header(enc_data, pwd)
        with open(fname + ".cant_read_this", "wb") as f:
            f.write(data_head)
            f.write(enc_data)
        return True, (data_head + enc_data)

    def handle_file(self, fname, out=None):
        if not os.path.isfile(fname):
            return False, "File doesn't exist"
        with open(fname, "rb") as f:
            data = f.read()
        return self.handle_data(data, out=out)

    def handle_data(self, data, out=None):
        #PROCESSED FILE TO RECOVER
        if self.test_processed(data):
            res = self.read_processed_data(data)
            if out is not None:
                with open(out, "wb") as f:
                    f.write(res[1])
            elif not TESTING:
                self.display_data(res[1])
            return res

        # PLAINDATA FILE TO PROCESS
        else:
            return self.process_plaindata(data, fname)

    def display_data(self, data):
        try:
            sys.stdout.write(str(data.decode()) + "\n")
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

    cr = CantReadThis()
    args = parser.parse_args()
    if args.testing:
        test()
    else:
        success, data = cr.handle_file(args.fname, out=args.outfile)
        if not success:
            print("Failed:\n\t" + data)

if __name__ == "__main__":
    main()
