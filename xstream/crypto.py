# -*- coding: utf-8 -*-
#14-6-20
# create by: snower

from M2Crypto import Rand,EVP

class Crypto(object):
    def __init__(self,key,alg='aes_256_cfb'):
        self._key=key
        self._alg=alg

    def init_encrypt(self):
        self._ensecret=(self.rand_string(32),self.rand_string(32))
        self._encipher=EVP.Cipher(self._alg,self._key,self._ensecret[0],1,1,'sha1',self._ensecret[1],1)
        return  "".join(self._ensecret)

    def init_decrypt(self,secret):
        self._desecret=(secret[:32],secret[32:])
        self._decipher=EVP.Cipher(self._alg,self._key,self._desecret[0],0,1,'sha1',self._desecret[1],1)

    def encrypt(self,data):
        return self._encipher.update(data)

    def decrypt(self,data):
        return self._decipher.update(data)

    def rand_string(self,length):
        return Rand.rand_bytes(length)