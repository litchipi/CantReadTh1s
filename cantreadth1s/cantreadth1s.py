#!/usr/bin/env python3
#-*-encoding:utf-8*-

import io
import os
import sys
import smaz
import time
import math
import json

import gzip
import zlib
import lzma
import lz4.frame

import argon2
import random
import getpass
import hashlib
import argparse
import traceback
from Crypto.Cipher import AES
import multiprocessing as mproc

VERSION = 0.4
TESTING = False

AES_BS = 16
pad = lambda s: s + ((AES_BS - len(s) % AES_BS) * chr(AES_BS - len(s) % AES_BS)).encode()
unpad = lambda s : s[0:-s[-1]]

ARGON2_DEFAULT_CONF = {"t":2, "m":1024, "p":(mproc.cpu_count()*2), "l":AES_BS}
ARGON2_CONF = dict.copy(ARGON2_DEFAULT_CONF)
SECURITY_LEVEL = 1

HEADER_SEPARATION_BYTES = bytes.fromhex("005EA7E800")
HEADER_SEPARATION_BYTES_LEN = len(HEADER_SEPARATION_BYTES)

RSIZE = (10*1024*1024)

WBITS = zlib.MAX_WBITS
#COMPRESSOR = zlib.compressobj(level=9, wbits = WBITS)
#DECOMPRESSOR = zlib.decompressobj(wbits = WBITS)
ZLIB_FLUSH_MODE = zlib.Z_SYNC_FLUSH
AES_HANDLER = None


#COMPRESSOR = bz2.BZ2Compressor()
#DECOMPRESSOR = bz2.BZ2Decompressor()


class C:
    def compress(self, d):
#        return bz2.compress(d)
        return d

class D:
    def decompress(self, d):
#        return bz2.decompress(d)
        return d

COMPRESSOR = None
DECOMPRESSOR = None
def init_compress():
    global COMPRESSOR
    global DECOMPRESSOR
    COMPRESSOR   = lzma.LZMACompressor()#zlib.compressobj()#lz4.frame.LZ4FrameCompressor(block_linked=False, auto_flush=False)
    DECOMPRESSOR = lzma.LZMADecompressor()#zlib.decompressobj()#lz4.frame.LZ4FrameDecompressor()

def test():
    cr = CantReadThis()
    cr.setup_aes_handler("a"*AES_BS)
    data = "tatatointointutu".encode()

    dclist = cr.prepare_datachunks([data for i in range(1000)], bs=16)
    
    res = list()
    f = list()
    for dc in dclist:
        c = cr.compress_datachunk(dc)
        e = cr.encrypt_datachunk(pad(c))
        f.append(e)
        d = unpad(cr.decrypt_datachunk(e))
        r = cr.decompress_datachunk(d)
        res.append(r)
    print("".encode().join([data for i in range(1000)]) == "".encode().join(res))
    print(sum([len(el) for el in f]), len(data)*1000)

class CantReadThis:
    def __init__(self):
        self.ncpu = mproc.cpu_count()
        self.tmp_file_data = {"filesize":None}
        self.rsize = RSIZE
        self.crumbs = dict()
        self.databuff = bytes()

    #AES encryption of a block of 16 bytes
    def setup_aes_handler(self, pwd):
        global AES_HANDLER
        AES_HANDLER = AES.new(pwd)

    def prepare_datachunks(self, bytelist, bs=1):
        buff = self.databuff + "".encode().join(bytelist)
        self.databuff = bytes()
        n = (len(buff)//self.ncpu)
        per_cpu = n - (n%bs)

        res = list([bytes() for i in range(self.ncpu)])
        for c in range(self.ncpu):
            res[c] = buff[(per_cpu*c):(per_cpu*(c+1))]
        if bs == 1:
            res[-1] += buff[(per_cpu*self.ncpu):]
            self.databuff = bytes()
        else:
            self.databuff = buff[(per_cpu*self.ncpu):]
        assert ("".encode().join(res) + self.databuff) == buff
        return res

    def compress_datachunk(self, data):
#        return gzip.compress(data)
#        return COMPRESSOR.compress(data)
        return COMPRESSOR.compress(data)

    def decompress_datachunk(self, data):
#        return gzip.decompress(data)
#        return DECOMPRESSOR.decompress(data)
        return DECOMPRESSOR.decompress(data)

    def encrypt_datachunk(self, data):
        return AES_HANDLER.encrypt(data)

    def decrypt_datachunk(self, data):
        return AES_HANDLER.decrypt(data)

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
                "i":info.replace(" ", "_"),
                "s":SECURITY_LEVEL,
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
            return hashlib.sha3_256(argon2.argon2_hash("CantReadTh1s_Password",
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

    def debug_data(self, data, name):
        pass#print(name, hashlib.sha256("".encode().join(data)).hexdigest())

    def load_processed_data(self, dataf, data_start, pwd, fout):
        with mproc.Pool(self.ncpu) as pool:
            dataf.seek(data_start)
            h = hashlib.sha256()
            finished = False
            init_compress()
            while not finished:
                data_chunks = list()
                for i in range(self.ncpu):
                    data_chunks.append((dataf.read(self.rsize),))

                n = dataf.tell()
                finished = (dataf.read(4) == "".encode())
                dataf.seek(n)

                data_chunks = [el for el in data_chunks if len(el[0]) > 0]
                if len(data_chunks) == 0: break
                if finished:
                    last_dc = data_chunks.pop(-1)

                decres = pool.starmap_async(self.decrypt_datachunk, data_chunks).get()
                if finished:
                    decres.append(unpad(self.decrypt_datachunk(*last_dc)))
                self.debug_data(decres, "dec")  #OK
                dmp_chunks = [(d,) for d in self.prepare_datachunks(decres)]

                self.debug_data([el[0] for el in dmp_chunks], "dmp")
                res = list()
                for n, d in enumerate(dmp_chunks):
                    res.append(self.decompress_datachunk(*d))
#                res = pool.starmap_async(self.decompress_datachunk, dmp_chunks).get()
                for n, r in enumerate(res):
                    fout.write(r)
                    h.update(r)
                print("")
        return h.hexdigest()

    def process_data(self, dataf, fout, pwd):
        with mproc.Pool(self.ncpu) as pool:
            dataf.seek(0)
            h = hashlib.sha256()
            finished = False
            self.databuff = bytes()
            init_compress()
            while not finished:
                data_chunks = list()
                for i in range(self.ncpu):
                    data_chunks.append((dataf.read(self.rsize),))

                n = dataf.tell()
                finished = (dataf.read(4) == "".encode())
                dataf.seek(n)
                data_chunks = [d for d in data_chunks if len(d[0]) > 0]

                cmpres = list()
                for n, d in enumerate(data_chunks):
                    cmpres.append(self.compress_datachunk(*d))
                cmp_chunks = [(d,) for d in self.prepare_datachunks(cmpres, bs=AES_BS)]
                res = pool.starmap_async(self.encrypt_datachunk, cmp_chunks).get()          #Encryption

                if finished:
                    self.databuff += COMPRESSOR.flush()
                    res.append(self.encrypt_datachunk(pad(self.databuff)))
                    self.databuff = bytes()
                for r in res:
                    fout.write(r)
                    h.update(r)
                print("")
        return h.hexdigest()

    def load_data(self, dataf, fout, display=False):
        success, data_start, header = self.header_check(dataf)
        if not success: return False, header
        change_security_level(int(header["s"]))
        if display:
            print("Information about the file:\n\t" + str(header["i"].replace("_", " ")))
            print("\n\t" + ",\n\t".join([str(k) + ": " + str(v) for k, v in header.items()]) + "\n")
        pwd, opt = self.ask_password("Enter password for data decryption: ", user_opt=header["a"])
        self.setup_aes_handler(pwd)
        checksum = self.load_processed_data(dataf, data_start, pwd, fout)
        if (header["h"] != checksum):
            print(header["h"])
            print(checksum)
            return False, "Wrong checksum"
        return True, fout

    def process_plaindata(self, dataf, fout, info=None, display=False, **kwargs):
        pwd, opt = self.ask_password("Enter password for data encryption: ")
        self.setup_aes_handler(pwd)
        datahash = self.compute_hash(dataf)
        data_head= self.create_header(datahash, pwd, opt, info)
        
        fout.write(data_head)
        try:
            checksum = self.process_data(dataf, fout, pwd)
        except:
            traceback.print_exc(file=sys.stdout)
            sys.exit(0)
        finally:
            fout.close()
        print(checksum)
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

        with open(fname, "rb") as f:
            try:
                processed = self.test_processed(f)
            except OSError:
                processed = False

        if processed:
            with open(fname, "rb") as f:
                return self.handle_processed_data(f, **kwargs)
        else:
            with open(fname, "rb") as dataf:
                with open(fname + ".cant_read_this", "wb") as fout:
                    success = self.process_plaindata(dataf, fout, **kwargs)
            if success and kwargs["display"]:
                src_sz = os.path.getsize(fname)
                dst_sz = os.path.getsize(fname + ".cant_read_this")
                ratio = round((float(dst_sz)/src_sz)*100,2)
                print("\nStored securely\n\t" + fname + ".cant_read_this" + "\n\t" + self.byte_to_measure(src_sz) + " -> " + self.byte_to_measure(dst_sz))
            if ret_data:
                with open(fname + ".cant_read_this", "rb") as f:
                    return success, f.read()
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
    n = SECURITY_LEVEL
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
    global SECURITY_LEVEL
    global ARGON2_DEFAULT_CONF
    SECURITY_LEVEL = int(level)
    ARGON2_CONF["t"] = int(ARGON2_DEFAULT_CONF["t"] + ((level-1)*2))
    ARGON2_CONF["m"] = int(ARGON2_DEFAULT_CONF["m"] + ((level-1)*256))
    ARGON2_CONF["l"] = int(ARGON2_DEFAULT_CONF["l"] + ((level-1)*AES_BS))

def fit_parameters(t):
    res = list()
    print("Starting parameters fitting to reach a hashing time of " + str(t) + " ms")
    n = 0; avg=0
    while True:
        try:
            change_security_level(max(1, avg-3))
            res.append(find_best_parameters_fit(t/1000))
            n += 1
            avg = int(round(sum(res)/len(res), 0))
            change_security_level(avg)
            sys.stdout.write("\033[2K\r")
            sys.stdout.write("(CTRL+C to stop) ")
            sys.stdout.write(str(n) + " iterations done | ")
            sys.stdout.write("Best level to fit: " + str(avg) + " | ")
            sys.stdout.write(", ".join([str(key) + ": " + str(val) for key, val in ARGON2_CONF.items()]) + "\t")
            sys.stdout.flush()
        except KeyboardInterrupt:
            break
    print("\nDone\n")


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
        return fit_parameters(args.find_parameters)

    change_security_level(args.security_level)
    success, res = cr.handle_file(args.fname, out=args.outfile, info=args.info, display=(args.outfile is None))
    if not success:
        print(res)

if __name__ == "__main__":
    main()
#    test()
