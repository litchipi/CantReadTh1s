#!/usr/bin/env python3
#-*-encoding:utf-8*-

import io
import os
import sys
import bz2
import smaz
import time
import math
import json
import lzma
import zlib
import argon2
import random
import zipfile
import getpass
import hashlib
import argparse
import lz4.frame
import traceback
from Crypto.Cipher import AES
import multiprocessing as mproc

VERSION = 0.5
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
ENCRYPTION_HANDLER = None
COMPRESSOR = None
DECOMPRESSOR = None

class LZ4Wrapper:
    def __init__(self, compress):
        self.beginned = False
        if compress:
            #self.obj = lz4.stream.LZ4StreamCompressor(strat, buffsize)
            self.obj = lz4.frame.LZ4FrameCompressor()
        else:
            #self.obj = lz4.stream.LZ4StreamDecompressor(strat, buffsize)
            self.obj = lz4.frame.LZ4FrameDecompressor()
    def compress(self, data):
        if not self.beginned:
            self.beginned = True
            return self.obj.begin() + self.obj.compress(data)
        return self.obj.compress(data)
    def decompress(self, data):
        return self.obj.decompress(data)
    def flush(self):
        return self.obj.flush()

class NoCompression:
    def compress(self, data):
        return data
    def flush(self):
        return bytes()
    def decompress(self, data):
        return data

def init_compress(ctype):
    global COMPRESSOR
    global DECOMPRESSOR
    if (ctype == "lzma"):
        COMPRESSOR   = lzma.LZMACompressor()
        DECOMPRESSOR = lzma.LZMADecompressor()
    elif (ctype == "bz2"):
        COMPRESSOR = bz2.BZ2Compressor()
        DECOMPRESSOR = bz2.BZ2Decompressor()
    elif (ctype == "zlib"):
        COMPRESSOR = zlib.compressobj(level=9)#ZlibWrapper(True)
        DECOMPRESSOR = zlib.decompressobj()#ZlibWrapper(False)
    elif (ctype == "lz4"):
        COMPRESSOR = LZ4Wrapper(True)#lz4.stream.LZ4StreamCompressor("double_buffer", 512)
        DECOMPRESSOR = LZ4Wrapper(False)#lz4.stream.LZ4StreamDecompressor("double_buffer", 512)
#    elif (ctype == "brotli"):
#        COMPRESSOR = brotli.brotli.Compressor()
#        DECOMPRESSOR = brotli.brotli.Decompressor()
    elif (ctype == "none"):
        COMPRESSOR = NoCompression()
        DECOMPRESSOR = NoCompression()
    else:
        COMPRESSOR = None
        DECOMPRESSOR = None

COMPRESSION_ALGORITHMS_AVAILABLE = ["lzma", "bz2", "zlib", "lz4", "none"]#"brotli", "none"]

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

    default_params = {
            "compression_algorithm":"zlib",
            }

    def __init__(self, preset_pwd=None, params={}):
        self.params = dict.copy(self.default_params)
        for k, v in params.items():
            if v is not None:
                self.params[k] = v

        self.ncpu = mproc.cpu_count()
        self.tmp_file_data = {"filesize":None}
        self.rsize = RSIZE
        self.crumbs = dict()
        self.databuff = bytes()
        self.preset_pwd = None
        if (preset_pwd is not None) and (preset_pwd != ""):
            self.preset_pwd = self.process_pwd(preset_pwd, ARGON2_CONF)[0]

    #AES encryption of a block of 16 bytes
    def setup_aes_handler(self, pwd):
        global ENCRYPTION_HANDLER
        ENCRYPTION_HANDLER = AES.new(pwd)

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
        return COMPRESSOR.compress(data)

    def decompress_datachunk(self, data):
        return DECOMPRESSOR.decompress(data)

    def encrypt_datachunk(self, data, n=0):
        if n == SECURITY_LEVEL:
            return data
        else:
            return ENCRYPTION_HANDLER.encrypt(self.encrypt_datachunk(data, n=n+1))

    def decrypt_datachunk(self, data, n=0):
        if n == SECURITY_LEVEL:
            return data
        else:
            return ENCRYPTION_HANDLER.decrypt(self.decrypt_datachunk(data, n=n+1))

    #Header compressed with smaz, light process for text compression
    def compress_text(self, data):
        return data.encode()
#        return smaz.compress(data)

    def decompress_text(self, data):
        return data.decode()
#        return smaz.decompress(data)

    def int_to_bytes(self, i):
        return int(i).to_bytes((i.bit_length()//8)+1, "big", signed=False)

    #Header format:
    #   header_length|smaz_compress({dict of header})
    def create_header(self, datahash, argon2_opt, info, isdir):
        if info is None: info = "Processed with CantReadThis v" + str(VERSION)
        header = {
                "h":datahash,
                "a":argon2_opt,
                "i":info.replace(" ", "_"),
                "s":SECURITY_LEVEL,
                "d":int(isdir),
                "c":COMPRESSION_ALGORITHMS_AVAILABLE.index(self.params["compression_algorithm"])
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
        opt = dict.copy(ARGON2_CONF)
        if user_opt is not None:
            opt.update(user_opt)
        return self.process_pwd(getpass.getpass(prompt), opt)

    def process_pwd(self, pwd, opt):
        return hashlib.sha3_256(argon2.argon2_hash("CantReadTh1s_Password",
                    hashlib.sha256(pwd.encode()).digest(),
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

    def load_processed_data(self, dataf, data_start, fout, compression_algorithm):
        with mproc.Pool(self.ncpu) as pool:
            dataf.seek(data_start)
            h = hashlib.sha256()
            finished = False
            init_compress(compression_algorithm)
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
                dmp_chunks = [(d,) for d in self.prepare_datachunks(decres)]

                res = list()
                for n, d in enumerate(dmp_chunks):
                    res.append(self.decompress_datachunk(*d))
#                res = pool.starmap_async(self.decompress_datachunk, dmp_chunks).get()
                for n, r in enumerate(res):
                    fout.write(r)
                    h.update(r)
        return h.hexdigest()

    def process_data(self, dataf, fout):
        with mproc.Pool(self.ncpu) as pool:
            dataf.seek(0)
            h = hashlib.sha256()
            finished = False
            self.databuff = bytes()
            init_compress(self.params["compression_algorithm"])
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
#                cmpres = pool.starmap_async(self.compress_datachunk, data_chunks).get()
                cmp_chunks = [(d,) for d in self.prepare_datachunks(cmpres, bs=AES_BS)]
                res = pool.starmap_async(self.encrypt_datachunk, cmp_chunks).get()          #Encryption

                if finished:
                    self.databuff += COMPRESSOR.flush()
                    res.append(self.encrypt_datachunk(pad(self.databuff)))
                    self.databuff = bytes()
                for r in res:
                    fout.write(r)
                    h.update(r)
        return h.hexdigest()

    def load_data(self, dataf, fout, display=False, verbose=False):
        success, data_start, header = self.header_check(dataf)
        if not success: return False, header, False
        change_security_level(int(header["s"]))
        if verbose:
            print("Information about the file:\n\t" + str(header["i"].replace("_", " ")))
            print("\n\t" + ",\n\t".join([str(k) + ": " + str(v) for k, v in header.items()]) + "\n")
        if self.preset_pwd is None:
            pwd, opt = self.ask_password("Enter password for data decryption: ", user_opt=header["a"])
        else:
            pwd = self.preset_pwd
        self.setup_aes_handler(pwd)
        checksum = self.load_processed_data(dataf, data_start, fout, COMPRESSION_ALGORITHMS_AVAILABLE[header["c"]])
        if (header["h"] != checksum[:8]):
            print(header["h"])
            print(checksum)
            return False, "Wrong checksum", False
        return True, fout, bool(header["d"])

    def process_plaindata(self, dataf, fout, info=None, display=False, isdir=False, **kwargs):
        if self.preset_pwd is None:
            pwd, opt = self.ask_password("Enter password for data encryption: ")
        else:
            pwd = self.preset_pwd
            opt = ARGON2_CONF
        self.setup_aes_handler(pwd)
        datahash = self.compute_hash(dataf)[:8]
        data_head= self.create_header(datahash, opt, info, isdir)
        
        fout.write(data_head)
        try:
            checksum = self.process_data(dataf, fout)
        except:
            traceback.print_exc(file=sys.stdout)
            sys.exit(0)
        finally:
            fout.close()
        if display:
            print(checksum)
        return True

    def display_time(self, nsecs):
        i = 0
        let = ["s", "m", "h"]
        nh = nsecs // 3600
        nsecs -= nh*3600
        nm = nsecs // 60
        nsecs -= nm*60
        res = ""
        prec = 3
        if nh != 0:
            res += str(nh) + "h "
            prec = 0
        if nm != 0:
            res += str(nm) + "m "
            prec = 0
        res += str(round(nsecs, prec)) + " secs"
        return res

    def handle_directory(self, fname, rsize=None, ret_data=False, **kwargs):
        pwd, opt = self.ask_password("Enter password for encryption of a whole folder: ")
        self.preset_pwd = pwd
        if fname[-1] == "/": fname = fname[:-1]
        ziph = zipfile.ZipFile(fname + "_zipfile", 'w', zipfile.ZIP_STORED)
        for root, dirs, files in os.walk(fname):
            for file in files:
                if not os.path.islink(os.path.join(root, file)):
                    ziph.write(os.path.join(root, file))
        ziph.close()
        res = self.handle_file(fname + "_zipfile", rsize=rsize, ret_data=ret_data, isdir=True, **kwargs)
        os.remove(fname + "_zipfile")
        return res

    def handle_file(self, fname, rsize=None, ret_data=False, out=None, **kwargs):
        t = time.time()
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
            if out is None:
                if ".cant_read_this" in fname:
                    out = fname.split(".cant_read_this")[0]
                else:
                    out = fname + ".recovered"
            with open(fname, "rb") as f:
                return self.handle_processed_data(f, out, **kwargs)
        else:
            with open(fname, "rb") as dataf:
                with open(fname + ".cant_read_this", "wb") as fout:
                    success = self.process_plaindata(dataf, fout, **kwargs)
            if success and kwargs["verbose"]:
                src_sz = os.path.getsize(fname)
                dst_sz = os.path.getsize(fname + ".cant_read_this")
                ratio = round(((float(dst_sz)/src_sz))*100,2)
                print("\nStored securely\n\t" + fname + ".cant_read_this" + "\n\t" + self.byte_to_measure(src_sz) + " -> " + self.byte_to_measure(dst_sz) + " "*5 + str(ratio) + "%")
                print("Done in " + self.display_time(time.time()-t))
            if ret_data:
                with open(fname + ".cant_read_this", "rb") as f:
                    return success, f.read()
            else:
                return True, ""

    def handle_processed_data(self, dataf, out, display=False, verbose=False, ret_data=False, **kwargs):
        t = time.time()
        if display:
            res = io.BytesIO()
        else:
            res = open(out, "w+b")

        try:
            success, res, isdir = self.load_data(dataf, res, display=display, verbose=verbose)
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

        if isdir:
            zipf = zipfile.ZipFile(out, 'r', zipfile.ZIP_STORED)
            zipf.extractall("./")
            zipf.close()
            os.remove(out)
        if verbose:
            print("Done in " + self.display_time(time.time()-t))
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
    res = list()
    n = 1
    d = io.BytesIO(os.urandom(1024*n))
    for i in range(20):
        d.seek(0)
        o = io.BytesIO()
        t = time.time()
        crt = CantReadThis(preset_pwd="password")
        crt.process_plaindata(d, o)
        dt = time.time() - t
        res.append(dt/n)
    return sum(res)/len(res)

def find_best_parameters_fit(t):
    n = SECURITY_LEVEL
    init = True
    oldres = 0; res = 0; msg=""
    print("")
    while init or (res < t):
        oldres = res
        res = benchmark()
        msg = ("\b"*len(msg))
        msg += "Level " + str(n) + ": " + str(round(res*1000, 5)) + "ms" + " "*5
        sys.stdout.write(msg)

        n += 1
        change_security_level(n)
        init = False
        time.sleep(0.25)

    if (abs(t-res) < abs(t-oldres)):
        return n-1
    else:
        return n-2

def change_security_level(level):
    global SECURITY_LEVEL
    global ARGON2_DEFAULT_CONF
    SECURITY_LEVEL = int(level)
    ARGON2_CONF["t"] = int(ARGON2_DEFAULT_CONF["t"] + ((level-1)*2))
    ARGON2_CONF["m"] = int(ARGON2_DEFAULT_CONF["m"] + ((level-1)*256))
    ARGON2_CONF["l"] = int(ARGON2_DEFAULT_CONF["l"] + ((level-1)*AES_BS))

def fit_parameters(t):
    res = list()
    print("Starting parameters fitting to reach a process time of " + str(t) + " ms / Kib")
    n = 0; avg=0
    while True:
        try:
            change_security_level(max(1, avg-3))
            res.append(find_best_parameters_fit(t/1000))
            n += 1
            avg = int(round(sum(res)/len(res), 0))
            change_security_level(avg)
            sys.stdout.write("\033[1A\033[2K\r")
            sys.stdout.write("(CTRL+C to stop) ")
            sys.stdout.write(str(n) + " iterations done | ")
            sys.stdout.write("Best level to fit: " + str(avg) + " | ")
            sys.stdout.write(", ".join([str(key) + ": " + str(val) for key, val in ARGON2_CONF.items()]) + "\t")
            sys.stdout.flush()
        except KeyboardInterrupt:
            break
    print("\nDone\n")

def print_version():
    print("CantReadThis version " + str(VERSION))
    print("Written by litchipi under GPLv3 license")
    print("litchi.pi@protonmail.com\t@LitchiPi\n")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--outfile', '-o', type=str, help='Where to save the recovered data')
    parser.add_argument('--display-only', '-d', help='Print result to stdout and do not write to file', action="store_true")
    parser.add_argument('--info', '-i', type=str, help='Information about the file, its content or an indication of the password')
    parser.add_argument('--security-level', '-l', type=int,
            help='Security level to use, changes the parameters of the password derivation function. Can go to infinite, default is 1.', default=1)
    parser.add_argument('--find-parameters', '-f', help='Tests the parameters needed to get the given execution time (in ms / Kib)', type=int)
    parser.add_argument('--compression-algorithm', '-c', help="The compression algorithm to use to process the data", type=str, choices=COMPRESSION_ALGORITHMS_AVAILABLE)
    parser.add_argument('--verbose', '-v', help="Display informations about the file and the process", action="store_true")
    parser.add_argument('--password', '-p', help='Password to use', type=str, default="")
    parser.add_argument("--version", "-V", help="Prints the current version", action="store_true")
    parser.add_argument('fname', metavar='filename', type=str, help="The file you want to process/recover", nargs="?")

    args = parser.parse_args()
    if args.version:
        print_version()
        sys.exit(0)
    elif args.find_parameters is not None:
        return fit_parameters(args.find_parameters)
    elif args.fname is None:
        print_version()
        parser.print_help()
        sys.exit(0)

    cr = CantReadThis(params=args.__dict__, preset_pwd=args.password)
    change_security_level(args.security_level)
    success, res = cr.handle_file(args.fname, out=args.outfile, info=args.info, display=args.display_only, verbose=args.verbose)
    if not success:
        print(res)

if __name__ == "__main__":
    main()
