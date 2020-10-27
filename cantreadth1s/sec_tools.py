import argon2
import base64
import hashlib

from multiprocessing import cpu_count

ARGON2_MIN_CONF = {"t":2, "m":1024, "l":256, "p":cpu_count()}
ARGON2_INCREASE = {"t":2, "m":512, "l":32, "p":0}

def generate_argon2_opts(level):
    return {k:int(ARGON2_MIN_CONF[k] + ((level-1)*ARGON2_INCREASE[k])) for k in ARGON2_MIN_CONF.keys()}

def derive_key(key, name, keylength=256, **argon2_cfg):
    hashlib.sha1("to".encode()).digest()
    return base64.b85encode(argon2.argon2_hash(
            hashlib.sha1(name.encode()).digest(),
            salt=hashlib.sha1(key.encode()).digest(),
            buflen=keylength,
            **argon2_cfg)).decode()

def process_pwd(pwd, opt, seed):
    return hashlib.sha3_256(argon2.argon2_hash(seed,
                hashlib.sha256(pwd.encode()).digest(),
                t=opt["t"], m=opt["m"], p=opt["p"], buflen=opt["l"])).digest()

