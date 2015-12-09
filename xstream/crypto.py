# _*_ coding: utf_8 _*_
#14_6_20
# create by: snower

import time
import random
import struct
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

def get_crypto_time(t = None):
    if t is None:
        return int(time.time())
    now = int(time.time())
    now_t = now & 0x3f
    if now_t >= t:
        return (now & 0xffffffc0) | (t & 0x3f)
    if t - now_t < 0x1f:
        return (now & 0xffffffc0) | (t & 0x3f) 
    return now - now_t - (0x40 - t)

def pack_protocel_code(crypto_time, action):
    rand_code = random.randint(0x001, 0x1ff)
    action_time = (crypto_time & 0x3f) | (action << 6)
    protecol_code = (rand_code << 7) | ((rand_code & 0xff) ^ action_time)
    return rand_code, struct.pack("!H", protecol_code)

def unpack_protocel_code(protecol_code):
    protecol_code, = struct.unpack("!H", protecol_code)
    rand_code = (protecol_code & 0xff80) >> 7
    action_time = ((protecol_code & 0xff) ^ (rand_code & 0xff)) & 0x7f
    crypto_time = get_crypto_time(action_time & 0x3f)
    return rand_code, ((action_time & 0x40) >> 6), crypto_time

class Crypto(object):
    def __init__(self, key, alg='aes_256_cfb'):
        self._key=key
        self._alg=alg

    def init_encrypt(self, crypto_time, secret=None):
        self._ensecret = (secret[:32], secret[32:]) if secret  and len(secret)>=64 else (rand_string(32), rand_string(32))
        self._encipher = EVP.Cipher(self._alg, self.bytes_to_key(self._ensecret[0], crypto_time), self._ensecret[1], 1, 0)
        return  "".join(self._ensecret)

    def init_decrypt(self, crypto_time, secret):
        self._desecret=(secret[:32], secret[32:])
        self._decipher=EVP.Cipher(self._alg, self.bytes_to_key(self._desecret[0], crypto_time), self._desecret[1], 0, 0)

    def encrypt(self, data):
        return self._encipher.update(data)

    def decrypt(self, data):
        return self._decipher.update(data)
    
    def bytes_to_key(self, salt, crypto_time):
        key_len = ALG_KEY_IV_LEN.get(self._alg)[0]
        d1, d2 = (self._key.encode('utf-8') if isinstance(self._key, unicode) else self._key), ''
        for i in range(5):
            s=EVP.MessageDigest('sha1')
            s.update("".join([d1, salt, str(crypto_time)]))
            d2=d1
            d1=s.digest()
        return (d1+d2)[:key_len]
