#!/usr/bin/env python3
#-*-encoding:utf-8*-

import io
import os
import sys
import zlib
import time
import math
import json
import base64
import string
import random
import zipfile
import getpass
import hashlib
import traceback
import multiprocessing as mproc

from .encryption import EncryptionWrapper
from .compression import CompressionWrapper
from .sec_tools import generate_argon2_opts, process_pwd, test_header_password, create_key_test_challenge
from .exceptions import BadPasswordException

VERSION = "0.6.2"
CRT_FILE_EXTENSION = ".crt"

def generate_random_fname(k=30):
    return "".join(random.choices(string.ascii_letters + string.digits, k=k))

class CantReadThis:
    default_params = {
            "compression_algorithm":"zlib",
            "info":VERSION,
            "header_misc_data":{},
            "fileobject":False,         #TODO
            "rsize":(512*1024),
            "security_level":1,
            "randomized_name":False,    #TODO
            "outfile":None,
            "debug":False,
            "verbose":False,
            "return_data":False,
            "argon2_params":None,
            "dict_to_binary":False,
            "max_password_tries":5,
            }

    def __init__(self, **kwparams):
        self.params = dict.copy(self.default_params)
        self.params.update({k:v for k, v in kwparams.items() if v is not None})

        # Parameters auto-generation
        if (self.params["argon2_params"] is None):
            self.params["argon2_params"] = generate_argon2_opts(self.params["security_level"])
        self.params["rsize"] = max(EncryptionWrapper.block_size,
                self.params["rsize"]-(self.params["rsize"]%EncryptionWrapper.block_size))


        self.ncpu = 1#mproc.cpu_count()
        self.preprocessed_pwd = None
        self.pwd_seed = None


######### ENCRYPTION / COMPRESSION / PASSWORD FUNCTIONS ######################
    def compress_header(self, header):
        return zlib.compress(json.dumps(header).replace(" ", "").encode())

    def decompress_header(self, header):
        return json.loads(zlib.decompress(header).decode())

    def compute_hash_dataf(self, dataf):
        dataf.seek(0)
        h = hashlib.sha256()
        dataread = dataf.read(self.params["rsize"])
        while (len(dataread) > 0):
            h.update(dataread)
            dataread = dataf.read(self.params["rsize"])
        dataf.seek(0)
        return h.hexdigest()

    def generate_seed(self):
        return os.urandom(4 + self.params["security_level"]).hex()

############# USEFULL MISC FUNCTIONS ################################

    def verify_checksum(self, c1, c2):
        if c1 != c2:
            if self.params["debug"]:
                print(c1)
                print(c2)
            raise Exception("Wrong checksum")

    def byte_to_measure(self, b, nprec=1):
        i = 0
        let = ["b", "K", "M", "G", "T", "P"]
        while b > 1024:
            b = b/1024
            i += 1
        return str(round(b, nprec)) + let[i]

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

    def __get_password(self, header, tries=1):
        if self.preprocessed_pwd is None:
            if "password" in self.params.keys():
                pwd = self.params["password"]
            else:
                if self.params["debug"]:
                    print("Nb tries: {}/{}".format(tries, self.params["max_password_tries"]))
                pwd = getpass.getpass("Password: ")
            self.preprocessed_pwd = process_pwd(pwd, header["a"], header["g"])
            if "t" in header.keys():        #Compatibility 0.6.1
                if not test_header_password(header, self.preprocessed_pwd):
                    if "password" in self.params.keys():
                        raise BadPasswordException("Wrong password")
                    elif (tries < self.params["max_password_tries"]):
                        print("Wrong password")
                        self.preprocessed_pwd = None
                        return self.__get_password(header, tries=(tries+1))
                    else:
                        raise BadPasswordException("Wrong password (too many retries)")
        return self.preprocessed_pwd

    def __set_password(self):
        if ((self.preprocessed_pwd is None) or (self.pwd_seed is None)):
            if "password" in self.params.keys():
                pwd = self.params["password"]
            else:
                pwd = getpass.getpass("Password: ")
            self.pwd_seed = self.generate_seed()
            self.preprocessed_pwd = process_pwd(pwd,
                    self.params["argon2_params"],
                    self.pwd_seed)
            self.key_test_challenge = create_key_test_challenge(self.preprocessed_pwd, self.params["argon2_params"], self.pwd_seed)

        return self.preprocessed_pwd

    def __extract_header_from_bin(self, obj):
        headerlen = int.from_bytes(obj[:4], "big", signed=False)
        header_bin = obj[4:(headerlen+4)]
        try:
            return self.decompress_header(header_bin), 4+headerlen
        except zlib.error:
            return None, None

    def __extract_header(self, fname):
        with open(fname, "rb") as dataf:
            dataf.seek(0)
            headerlen = int.from_bytes(dataf.read(4), "big", signed=False)
            header_bin = dataf.read(headerlen)
        try:
            return self.decompress_header(header_bin), 4+headerlen
        except zlib.error:
            return None, None

    def __get_outfname(self, fname, load=False):
        if load:
            if CRT_FILE_EXTENSION in fname:
                return fname.split(CRT_FILE_EXTENSION)[0]
            else:
                return fname + ".recovered"
        else:
            if self.params["randomized_name"]:
                return generate_random_fname()
            elif self.params["outfile"] is not None:
                return self.params["outfile"] + CRT_FILE_EXTENSION*(CRT_FILE_EXTENSION not in self.params["outfile"])
            else:
                return fname + CRT_FILE_EXTENSION

    def display_file_informations(self, fname, header):
        if not self.params["verbose"]:
            return
        print("Information about the file:\n\t" + str(header["i"].replace("_", " ")))
        if self.params["debug"]:
            print("\n\t" + ",\n\t".join([str(k) + ": " + str(v) for k, v in header.items()]) + "\n")

    def __data_load(self, fin, fout, header, datastart):
        h = hashlib.sha256()
        ndata = (self.params["rsize"] * self.ncpu)
        fin.seek(datastart)
        finished = False
        n = 0
        while not finished:
            data = fin.read(ndata)
            if self.params["debug"]:
                print("l loop", n, len(data), ndata, len(data) < ndata, fin.tell())
                n += 1
            finished = (len(data) < ndata)
            dec_data = self.enc.decrypt(data)
            if finished:
                dec_data += self.enc.dec_finish()
            dcp_data = self.cmp.decompress(dec_data)
            if finished:
                dcp_data += self.cmp.dcp_finish()
            h.update(dcp_data)
            fout.write(dcp_data)
        return h.hexdigest()

    def __data_process(self, fin, fout):
        h = hashlib.sha256()        #Doesn't work
        if self.params["debug"]:
            h2 = hashlib.sha256()
        ndata = (self.params["rsize"] * self.ncpu)
        fin.seek(0)
        finished = False
        n = 0
        while not finished:
            data = fin.read(ndata)
            if self.params["debug"]:
                print("p loop", n, len(data), ndata, len(data) < ndata, fin.tell())
                n += 1
            h.update(data)
            finished = (len(data) < ndata)
            cmp_data = self.cmp.compress(data)
            if finished:
                cmp_data += self.cmp.cmp_finish()
            enc_data = self.enc.encrypt(cmp_data)
            if finished:
                enc_data += self.enc.enc_finish()
            if self.params["debug"]:
                h2.update(enc_data)
            fout.write(enc_data)
        if self.params["debug"]:
            print("Encrypted data checksum: ", h2.hexdigest())
        return h.hexdigest()

    def is_misc_data(self, header, dataname):
        return ("m" in header.keys()) and (dataname in header["m"].keys())

    def unzip_file(self, fname):
        ziph = zipfile.ZipFile(fname, 'r', zipfile.ZIP_STORED)
        ziph.extractall()
        ziph.close()
        os.remove(fname)

    def __load_crt(self, fname):
        header, datastart = self.__extract_header(fname)
        if header is None: return False, "Cannot recover the header"
        pwd = self.__get_password(header)
        t = time.time()
        self.display_file_informations(fname, header)

        checksum = ""
        if self.is_misc_data(header, "original_fname"):
            out_fname = header["m"]["original_fname"]
        elif self.is_misc_data(header, "is_dir"):
            out_fname = fname + ".zip"
        else:
            out_fname = self.__get_outfname(fname, load=True)

        if (self.params["fileobject"] or self.params["return_data"]) and not self.is_misc_data(header, "is_dir"):
            out = io.BytesIO()
        else:
            out = open(out_fname, "w+b")
        try:
            self.enc = EncryptionWrapper(self.ncpu, pwd, iv=header["v"])
            self.cmp = CompressionWrapper(self.ncpu, int(header["c"]))
            with open(fname, "rb") as dataf:
                checksum = self.__data_load(dataf, out, header, datastart)
            self.verify_checksum(checksum, header["h"])
            if self.params["verbose"]:
                print("Done in " + self.display_time(time.time()-t))
        finally:
            if self.params["return_data"]:
                out.seek(0)
                result = out.read()
            out.close()

        if self.is_misc_data(header, "is_dir"):
            self.unzip_file(out_fname)
        if self.params["return_data"]:
            return True, result
        return True, out

    def __create_header_dict(self, checksum):
        header = {
                "v":self.enc.iv,
                "g":self.pwd_seed,
                "h":checksum,
                "a":self.params["argon2_params"],
                "i":self.params["info"].replace(" ", "_"),
                "s":self.params["security_level"],
                "c":CompressionWrapper.COMPRESSION_ALGORITHMS_AVAILABLE.index(self.params["compression_algorithm"]),
                "t":self.key_test_challenge
                }
        if len(self.params["header_misc_data"]) > 0:
            header["m"] = dict.copy(self.params["header_misc_data"])
        return header

    def __create_header_bin(self, checksum):
        header = self.__create_header_dict(checksum)
        bin_head = self.compress_header(header)
        if self.params["debug"]:
            print("HEADER LEN ", len(bin_head))
        return len(bin_head).to_bytes(4, "big", signed=False) + bin_head

    def __process_crt(self, fname):
        pwd = self.__set_password()
        t = time.time()
        success = False

        outfname = self.__get_outfname(fname, load=False)
        if self.params["fileobject"] or self.params["return_data"]:
            outf = io.BytesIO()
        else:
            outf = open(outfname, "w+b")
        try:
            self.enc = EncryptionWrapper(self.ncpu, pwd)
            self.cmp = CompressionWrapper(self.ncpu, CompressionWrapper.COMPRESSION_ALGORITHMS_AVAILABLE.index(self.params["compression_algorithm"]))
            with open(fname, "rb") as dataf:
                checksum_exp = self.compute_hash_dataf(dataf)
                header_bin = self.__create_header_bin(checksum_exp)
                outf.write(header_bin)
                checksum_got = self.__data_process(dataf, outf)
            if self.params["verbose"]:
                print("Done in " + self.display_time(time.time()-t))
            success = True
            self.verify_checksum(checksum_exp, checksum_got)
        finally:
            if self.params["return_data"]:
                outf.seek(0)
                result = outf.read()
            outf.close()
        self.display_process_stats(fname, outfname)
        if self.params["return_data"]:
            return success, result
        return success, outf


    def handle_directory(self, fname):
        self.__set_password()
        fname = os.path.abspath(fname)
        self.params["header_misc_data"]["is_dir"] = True
        zip_root = os.path.abspath(os.path.curdir)
        ziph = zipfile.ZipFile(fname + ".dir", 'w', zipfile.ZIP_STORED)
        for root, dirs, files in os.walk(fname):
            ziph.write(root.replace(zip_root, "."))
            for f in files:
                if not os.path.islink(os.path.join(root, f)):
                    ziph.write(os.path.join(root, f).replace(zip_root, "."))
        ziph.close()

        res = self.handle_file(fname + ".dir")
        os.remove(fname + ".dir")
        return res

    def test_processed(self, dataf):
        dataf.seek(0, 2)
        fsize = dataf.tell()
        dataf.seek(0)
        headerlen = int.from_bytes(dataf.read(4), "big", signed=False)
        if (headerlen >= fsize):
            return False
        header_bin = dataf.read(headerlen)
        try:
            self.decompress_header(header_bin)
            return True
        except zlib.error:
            return False

    def __dict_data_load(self, data, header, decoded=False):
        if not decoded:
            data = base64.b85decode(data)
        cmpdata = self.enc.decrypt(data) + self.enc.dec_finish()
        rawdata = self.cmp.decompress(cmpdata) + self.cmp.dcp_finish()
        result = json.loads(rawdata.decode())
        return hashlib.sha256(rawdata).hexdigest(), result

    def __dict_data_process(self, obj):
        rawdata = json.dumps(obj).encode()
        cmpdata = self.cmp.compress(rawdata) + self.cmp.cmp_finish()
        encdata = self.enc.encrypt(cmpdata) + self.enc.enc_finish()
        checksum = hashlib.sha256(rawdata).hexdigest()
        if self.params["dict_to_binary"]:
            return checksum, encdata
        else:
            return checksum, base64.b85encode(encdata).decode()

    def __dict_load_crt(self, data, header):
        pwd = self.__get_password(header)
        t = time.time()

        self.enc = EncryptionWrapper(self.ncpu, pwd, iv=header["v"])
        self.cmp = CompressionWrapper(self.ncpu, int(header["c"]))
        checksum, result = self.__dict_data_load(data, header)
        self.verify_checksum(checksum, header["h"])
        if self.params["verbose"]:
            print("Done in " + self.display_time(time.time()-t))
        return True, result


    def __dict_process_crt(self, data):
        pwd = self.__set_password()
        t = time.time()

        self.enc = EncryptionWrapper(self.ncpu, pwd)
        self.cmp = CompressionWrapper(self.ncpu,
                CompressionWrapper.COMPRESSION_ALGORITHMS_AVAILABLE.index(self.params["compression_algorithm"]))
        checksum, result = self.__dict_data_process(data)
        if self.params["dict_to_binary"]:
            header = self.__create_header_bin(checksum)
            return True, header + result
        else:
            header = self.__create_header_dict(checksum)
            return True, {"__crt__":header, "__data__":result}

    def is_processed_dict(self, obj):
        return (type(obj) == dict) and all([el in obj.keys() for el in ["__crt__", "__data__"]])

    def handle_dict_from_binary(self, obj):
        try:
            header, datastart = self.__extract_header_from_bin(obj)
            if header is None:
                raise Exception("Cannot recover header")
            pwd = self.__get_password(header)

            self.enc = EncryptionWrapper(self.ncpu, pwd, iv=header["v"])
            self.cmp = CompressionWrapper(self.ncpu, int(header["c"]))
            checksum, result = self.__dict_data_load(obj[datastart:], header, decoded=True)
            self.verify_checksum(checksum, header["h"])
            return result
        except Exception as err:
            if self.params["debug"]:
                print("Exception occured", err)
                traceback.print_exc(file=sys.stdout)
            return None

    def handle_dict(self, obj):
        processed = self.is_processed_dict(obj)
        if processed:
            if self.params["debug"]:
                print("processed", obj)
            success, result = self.__dict_load_crt(obj.pop("__data__"), obj.pop("__crt__"))
            obj.update(result)
            return obj
        else:
            if self.params["debug"]:
                print("Not processed")
            success, result = self.__dict_process_crt(obj)
            return result

    def handle_file(self, flist):
        if type(flist) == str:
            return self.handle_file([flist])

        if len(flist) > 1:
            results = list()
            for f in flist:
                res = self.handle_file([f])
                if not res[0]:
                    return res
                results.append(res[1])
            return True, results
        else:
            fname = flist[0]

        if self.params["debug"]:
            print("Taking care of file " + fname)

        if not os.path.isfile(fname):
            if not os.path.isdir(fname):
                return False, "File " + fname + " doesn't exist"
            else:
                return self.handle_directory(fname)

        if self.params["debug"]:
            print("Parameters passed: ", self.params)
            #print("\n".join(["\t{}: {}".format(key, val) for key, val in self.params.items()]))

        with open(fname, "rb") as f:
            try:
                processed = self.test_processed(f)
            except OSError:
                processed = False

        try:
            if processed:
                return self.__load_crt(fname)
            else:
                return self.__process_crt(fname)
        except Exception as err:
            if self.params["debug"]:
                traceback.print_exc(file=sys.stdout)
            return False, str(err)

    def display_process_stats(self, src, dst):
        if not self.params["verbose"]:
            return
        src_sz = os.path.getsize(src)
        dst_sz = os.path.getsize(dst)
        if (src_sz == 0): ratio = 0
        else:
            ratio = round((float(dst_sz)/src_sz)*100, 2)
        print("\t{} [{}] -> {} [{}] ({}% compression)".format(os.path.basename(src), self.byte_to_measure(src_sz),
            os.path.basename(dst), self.byte_to_measure(dst_sz), ratio))
