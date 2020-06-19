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
import gzip
from Crypto.Cipher import AES
import argon2
import multiprocessing as mproc

VERSION = 0.3
TESTING = False

AES_BS = 16
pad = lambda s: s + ((AES_BS - len(s) % AES_BS) * chr(AES_BS - len(s) % AES_BS)).encode()
unpad = lambda s : s[0:-s[-1]]

ARGON2_DEFAULT_CONF = {"t":128, "m":32, "p":8}
HEADER_SEPARATION_BYTES = bytes.fromhex("005EA7E800")
HEADER_SEPARATION_BYTES_LEN = len(HEADER_SEPARATION_BYTES)

def open_compressed_file(*args, **kwargs):
    kwargs["compresslevel"] = 9
    return gzip.open(*args, **kwargs)

class CantReadThis:

    def __init__(self):
        self.ncpu = mproc.cpu_count()
        self.tmp_file_data = {"filesize":None}
        self.rsize = (10*1024*1024)

    #AES encryption of a block of 16 bytes
    def encrypt_data(self, data, pwd):
        return AES.new(pwd).encrypt(data)

    def decrypt_data(self, data, pwd):
        return AES.new(pwd).decrypt(data)

    #Header compressed with smaz, light process for text compression
    def compress_text(self, data):
        return smaz.compress(data)

    def decompress_text(self, data):
        return smaz.decompress(data)

    def int_to_bytes(self, i):
        return int(i).to_bytes((i.bit_length()//8), "big", signed=False)

    #Header format:
    #   header_length|smaz_compress({dict of header})
    def create_header(self, datahash, pwd, argon2_opt, info):
        if info is None: info = "Processed with CantReadThis v" + str(VERSION)
        header = {
                "h":datahash,
                "a":argon2_opt,
                "i":info.replace(" ", "_")
                }
        bin_head = self.compress_text(json.dumps(header).replace(" ", ""))
        if TESTING:
            print(len(json.dumps(header).replace(" ", "")), len(bin_head), 100*(len(json.dumps(header).replace(" ", ""))/len(bin_head)))
        res = self.int_to_bytes(len(bin_head)) + HEADER_SEPARATION_BYTES + bin_head
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
        while ((dread is None) or (dread != HEADER_SEPARATION_BYTES)):
            dread = dataf.read(HEADER_SEPARATION_BYTES_LEN)
            if (len(dread) == 0) or (n >= 10):
                return None, 0
            n += 1
            dataf.seek(n)
        dataf.seek(0)
        headerlen_bin = dataf.read(n-1)
        headerlen = int.from_bytes(headerlen_bin, "big", signed=False)
        dataf.seek(len(headerlen_bin)+HEADER_SEPARATION_BYTES_LEN)
        header_bin = dataf.read(headerlen)
        return json.loads(self.decompress_text(header_bin)), len(headerlen_bin)+HEADER_SEPARATION_BYTES_LEN+headerlen

    def compute_hash(self, dataf):
        h = hashlib.sha256(dataf.read(self.rsize))
        dataread = dataf.read(self.rsize)
        while (len(dataread) > 0):
            h.update(dataread)
            dataread = dataf.read(self.rsize)
        return h.hexdigest()

    def header_check(self, dataf):
        header, data_start = self.extract_header(dataf)
        if header is None:
            return False, -1, "Header cannot be extracted from file"
        return True, data_start, header

    def byte_to_measure(self, b, nprec=1):
        i = 0
        let = ["b", "K", "M", "G", "T", "P"]
        while b > 1024:
            b = b/1024
            i += 1
        return str(round(b, nprec)) + let[i]

    def load_processed_data(self, dataf, data_start, pwd, fout):
        with mproc.Pool(self.ncpu) as pool:
            dataf.seek(data_start)
            h = hashlib.sha256()
            finished = False
            while not finished:
                data_chunks = list()
                for i in range(self.ncpu):
                    data_chunks.append((dataf.read(self.rsize), pwd))

                n = dataf.tell()
                finished = (dataf.read(4) == "".encode())
                dataf.seek(n)

                data_chunks = [el for el in data_chunks if len(el[0]) > 0]
                res = pool.starmap(self.decrypt_data, data_chunks)
                for n, r in enumerate(res):
                    if finished and (n == (len(res)-1)):
                        r = unpad(r)
                    fout.write(r)
                    h.update(r)
        return h.hexdigest()

    def process_data(self, dataf, fout, pwd):
        with mproc.Pool(self.ncpu) as pool:
            dataf.seek(0)
            finished = False
            while not finished:
                data_chunks = list()
                for i in range(self.ncpu):
                    data_chunks.append((dataf.read(self.rsize), pwd))

                n = dataf.tell()
                finished = (dataf.read(4) == "".encode())
                dataf.seek(n)
                data_chunks = [(d, pwd) for d, pwd in data_chunks if len(d) > 0]
                if finished:
                    data_chunks[-1] = (pad(data_chunks[-1][0]), pwd)
                res = pool.starmap_async(self.encrypt_data, data_chunks)
                for r in res.get():
                    fout.write(r)

    def load_data(self, dataf, fout, display=False):
        success, data_start, header = self.header_check(dataf)
        if not success: return False, header
        if display:
            print("Information about the file:\n\t" + str(header["i"].replace("_", " ")))
        pwd, opt = self.ask_password("Enter password for data decryption: ", opt=header["a"])
        checksum = self.load_processed_data(dataf, data_start, pwd, fout)
        if (header["h"] != checksum):
            print(header["h"])
            print(checksum)
            return False, "Wrong checksum"
        return True, fout



    def process_plaindata(self, dataf, fout, info=None, display=False, **kwargs):
        pwd, opt = self.ask_password("Enter password for data encryption: ")
        datahash = self.compute_hash(dataf)
        data_head= self.create_header(datahash, pwd, opt, info)
        
        fout.write(data_head)
        self.process_data(dataf, fout, pwd)
        fout.close()
        print(datahash)
        return True

    def handle_directory(self, fname, rsize=None, ret_data=False, **kwargs):
        # Zip the whole directory without compression (do not follow symlinks)
        #   Then process the file
        return False, "Not implemented yet"

    def handle_file(self, fname, rsize=None, ret_data=False, **kwargs):
        if not os.path.isfile(fname):
            if not os.path.isdir(fname):
                return False, "File doesn't exist"
            else:
                return self.handle_directory(fname, rsize=rsize, ret_data=ret_data, **kwargs)

        self.tmp_file_data["filesize"] = os.path.getsize(fname)
        if rsize is not None:
            self.rsize = rsize
        self.rsize = self.rsize-(self.rsize%16)

        with open_compressed_file(fname, "rb") as f:
            try:
                processed = self.test_processed(f)
            except OSError:
                processed = False

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
            else:
                return True, ""

    def handle_processed_data(self, dataf, out=None, display=False, ret_data=False, **kwargs):
        if out is not None:
            res = open(out, "w+b")
        elif display:
            res = io.BytesIO()

        try:
            success, res = self.load_data(dataf, res, display=display)
            if not success:
                return False, res

            if display:
                res.seek(0)
                self.display_data(res.read())

            if ret_data:
                res.seek(0)
                ret = res.read()

        finally:
            try:
                res.close()
            except:
                pass

        if ret_data:
            return True, ret
        return True, None

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
        success, res = cr.handle_file(args.fname, out=args.outfile, info=args.info, display=(args.outfile is None))
        if not success:
            print(res)

if __name__ == "__main__":
    main()
