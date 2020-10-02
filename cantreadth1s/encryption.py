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

    def pad(self, s):
        return s + ((self.block_size - len(s) % self.block_size) * chr(self.block_size - len(s) % self.block_size)).encode()

    def unpad(self, s):
        return s[0:-s[-1]]

    def encrypt(self, data):
        enc = self.cipher.encryptor()
        return enc.update(data) + enc.finalize()

    def decrypt(self, data):
        dec = self.cipher.decryptor()
        return dec.update(data) + dec.finalize()


