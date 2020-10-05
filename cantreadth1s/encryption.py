import os
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class EncryptionWrapper:
    block_size = algorithms.AES.block_size
    def __init__(self, ncpu, pwd, iv=None):
        if iv is None:
            iv = base64.b85encode(os.urandom(self.block_size//8)).decode()
        self.iv = iv
        self.ncpu = ncpu
        self.algo = algorithms.AES(pwd)
        self.cipher = Cipher(self.algo, modes.CFB(base64.b85decode(self.iv)))
        self.init_enc_dec()

    def init_enc_dec(self):
        self.enc = self.cipher.encryptor()
        self.dec = self.cipher.decryptor()

    def encrypt(self, data):
        return self.enc.update(data)

    def decrypt(self, data):
        return self.dec.update(data)

    def enc_finish(self):
        return self.enc.finalize()

    def dec_finish(self):
        return self.dec.finalize()
