import os
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class EncryptionWrapper:
    block_size = algorithms.AES.block_size
    def __init__(self, ncpu, pwd, sec_level, iv=None):
        if iv is None:
            iv = base64.b64encode(os.urandom(self.block_size//8)).decode()
        self.iv = iv
        self.sec_level = sec_level
        self.ncpu = ncpu
        self.cipher = Cipher(algorithms.AES(pwd), modes.OFB(base64.b64decode(self.iv)))

    def encrypt(self, data, n=0):
        if (n == self.sec_level):
            return data
        enc = self.cipher.encryptor()
        return self.encrypt(enc.update(data) + enc.finalize(), n=n+1)

    def decrypt(self, data, n=0):
        if (n == self.sec_level):
            return data
        dec = self.cipher.decryptor()
        return self.decrypt(dec.update(data) + dec.finalize(), n=n+1)
