#!/usr/bin/env python3
#-*-encoding:utf-8*-

import io
import os
import sys
import smaz
import time
import json
import gzip
import argon2
import random
import getpass
import hashlib
import argparse
from Crypto.Cipher import AES
import multiprocessing as mproc

VERSION = 0.4
TESTING = False

AES_BS = 16
pad = lambda s: s + ((AES_BS - len(s) % AES_BS) * chr(AES_BS - len(s) % AES_BS)).encode()
unpad = lambda s : s[0:-s[-1]]

ARGON2_DEFAULT_CONF = {"t":2, "m":1024, "p":(mproc.cpu_count()*2), "l":AES_BS}
ARGON2_CONF = dict.copy(ARGON2_DEFAULT_CONF)

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

    def ask_password(self, prompt, user_opt=None):
        if TESTING:
            return self.compute_hash("tata".encode())
        else:
            opt = dict.copy(ARGON2_CONF)
            if user_opt is not None:
                opt.update(user_opt)
            return hashlib.sha256(argon2.argon2_hash("CantReadTh1s_Password",
                        hashlib.sha256(getpass.getpass(prompt).encode()).digest(), 
                        t=opt["t"], m=opt["m"], p=opt["p"], buflen=opt["l"])).digest(), opt

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
            print("\n\t" + ",\n\t".join([str(k) + ": " + str(v) for k, v in header.items()]) + "\n")
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

def benchmark():
    opt = dict.copy(ARGON2_CONF)
    t = time.time()
    res = argon2.argon2_hash("CantReadTh1s_Password",
            hashlib.sha256("tata".encode()).digest(), t=opt["t"], m=opt["m"], p=opt["p"], buflen=opt["l"])
    dt = time.time() - t
    return dt

def find_best_parameters_fit(t):
    n = 1
    init = True
    oldres = 0; res = 0
    while init or (res < t):
        oldres = res
        res = benchmark()
        n += 1
        change_security_level(n)
        init = False

    if (abs(t-res) < abs(t-oldres)):
        return n-1
    else:
        return n-2

def change_security_level(level):
    #"t":2, "m":1024, "p":(mproc.cpu_count()*2)
    global ARGON2_DEFAULT_CONF
    ARGON2_CONF["t"] = ARGON2_DEFAULT_CONF["t"] + ((level-1)*2)
    ARGON2_CONF["m"] = ARGON2_DEFAULT_CONF["m"] + ((level-1)*256)
    ARGON2_CONF["l"] = ARGON2_DEFAULT_CONF["l"] + ((level-1)*AES_BS)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('fname', metavar='filename', type=str, help="The file you want to process/recover")
    parser.add_argument('--outfile', '-o', type=str, help='Where to save the recovered data (if nothing is passed, will print it in stdout)')
    parser.add_argument('--info', '-i', type=str, help='Information about the file, its content or an indication of the password')
    parser.add_argument('--security-level', '-l', type=int,
            help='Security level to use, changes the parameters of the password derivation function. Can go to infinite, default is 1.', default=1)
    parser.add_argument('--find-parameters', '-f', help='Tests the parameters needed to get the given execution time (in ms)', type=int)

    cr = CantReadThis()
    args = parser.parse_args()

    if args.find_parameters is not None:
        res = list()
        while True:
            try:
                change_security_level(1)
                res.append(find_best_parameters_fit(args.find_parameters/1000))
                avg = round(sum(res)/len(res), 0)
                change_security_level(avg)
                sys.stdout.write("\033[2K\r")
                sys.stdout.write("(CTRL+C to stop) ")
                sys.stdout.write("Best level to fit: " + str(avg))
                sys.stdout.write(" | ")
                sys.stdout.write(", ".join([str(key) + ": " + str(val) for key, val in ARGON2_CONF.items()]) + "\t")
                sys.stdout.flush()
            except KeyboardInterrupt:
                break
        print("\nDone\n")
        return

    change_security_level(args.security_level)
    success, res = cr.handle_file(args.fname, out=args.outfile, info=args.info, display=(args.outfile is None))
    if not success:
        print(res)

if __name__ == "__main__":
    main()
