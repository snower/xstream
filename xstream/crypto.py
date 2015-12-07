# _*_ coding: utf_8 _*_
#14_6_20
# create by: snower

import time
import datetime
from M2Crypto import Rand,EVP

ALG_KEY_IV_LEN = {
    'aes_128_cfb': (16, 16),
    'aes_192_cfb': (24, 16),
    'aes_256_cfb': (32, 16),
    'bf_cfb': (16, 8),
    'camellia_128_cfb': (16, 16),
    'camellia_192_cfb': (24, 16),
    'camellia_256_cfb': (32, 16),
    'cast5_cfb': (16, 8),
    'des_cfb': (8, 8),
    'idea_cfb': (16, 8),
    'rc2_cfb': (8, 8),
    'rc4': (16, 0),
    'seed_cfb': (16, 16),
}

def rand_string(length):
    return Rand.rand_bytes(length)

def xor_string(key, data, encrypt=True):
    if isinstance(key, basestring):
        key = ord(key[0])
    result = []
    for c in data:
        r = ord(c) ^ key
        result.append(chr(r))
        key = r if encrypt else ord(c)
    return "".join(result)

def sign_string(data):
    for t in ("md5", "sha1", "md5"):
        s=EVP.MessageDigest(t)
        s.update(data)
        data=s.digest()
    return data

def get_crypto_time():
    dt = datetime.datetime.now() - datetime.timedelta(seconds=5)
    dt = datetime.datetime(dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second - dt.second % 10)
    return int(time.mktime(dt.timetuple()))

class Crypto(object):
    def __init__(self, key, alg='aes_256_cfb'):
        self._key=key
        self._alg=alg

    def init_encrypt(self, secret=None):
        self._ensecret = (secret[:32], secret[32:]) if secret  and len(secret)>=64 else (rand_string(32), rand_string(32))
        self._encipher = EVP.Cipher(self._alg, self.bytes_to_key(self._ensecret[0]), self._ensecret[1], 1, 0)
        return  "".join(self._ensecret)

    def init_decrypt(self, secret):
        self._desecret=(secret[:32], secret[32:])
        self._decipher=EVP.Cipher(self._alg, self.bytes_to_key(self._desecret[0]), self._desecret[1], 0, 0)

    def encrypt(self, data):
        return self._encipher.update(data)

    def decrypt(self, data):
        return self._decipher.update(data)
    
    def bytes_to_key(self, salt):
        key_len = ALG_KEY_IV_LEN.get(self._alg)[0]
        d1, d2 = (self._key.encode('utf-8') if isinstance(self._key, unicode) else self._key), ''
        crypto_time = str(get_crypto_time())
        for i in range(5):
            s=EVP.MessageDigest('sha1')
            s.update("".join([d1, salt, crypto_time]))
            d2=d1
            d1=s.digest()
        return (d1+d2)[:key_len]
