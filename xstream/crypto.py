# _*_ coding: utf_8 _*_
#14_6_20
# create by: snower

import os
import time
import random
import struct

ALG_KEY_IV_LEN = {
        'aes_128_cfb': (16, 16),
        'aes_192_cfb': (24, 16),
        'aes_256_cfb': (32, 16),
        'aes_128_ofb': (16, 16),
        'aes_192_ofb': (24, 16),
        'aes_256_ofb': (32, 16),
        'aes_128_ctr': (16, 16),
        'aes_192_ctr': (24, 16),
        'aes_256_ctr': (32, 16),
        'aes_128_cfb8': (16, 16),
        'aes_192_cfb8': (24, 16),
        'aes_256_cfb8': (32, 16),
        'aes_128_cfb1': (16, 16),
        'aes_192_cfb1': (24, 16),
        'aes_256_cfb1': (32, 16),
        'bf_cfb': (16, 8),
        'camellia_128_cfb': (16, 16),
        'camellia_192_cfb': (24, 16),
        'camellia_256_cfb': (32, 16),
        'cast5_cfb': (16, 8),
        'des_cfb': (8, 8),
        'idea_cfb': (16, 8),
        'rc2_cfb': (16, 8),
        'rc4': (16, 0),
        'seed_cfb': (16, 16),
    }

if os.environ.get("XSTREAM_CRYPTO", "m2crypto").lower() == "m2crypto":
    from M2Crypto import Rand,EVP

    def get_evp(alg_key, key, iv, op):
        if alg_key not in ALG_KEY_IV_LEN:
            return
        return EVP.Cipher(alg_key, key, iv, op, 0)

    def rand_string(length):
        return Rand.rand_bytes(length)

    def sign_string(data):
        d = ''
        for t in ("md5", "sha1", "md5"):
            s = EVP.MessageDigest(t)
            s.update(data + d)
            d = s.digest()
        return d

    def bytes_to_key_digest():
        return EVP.MessageDigest('sha1')

else:
    import hashlib
    from .openssl import OpenSSLCrypto

    def get_evp(alg_key, key, iv, op):
        if alg_key not in ALG_KEY_IV_LEN:
            return
        return OpenSSLCrypto(alg_key.replace("_", "-"), key, iv, op)

    def rand_string(length):
        return "".join([chr(random.randint(0, 255)) for _ in xrange(length)])

    def sign_string(data):
        d = ''
        for t in (hashlib.md5, hashlib.sha1, hashlib.md5):
            s = t()
            s.update(data + d)
            d = s.digest()
        return d

    def bytes_to_key_digest():
        return hashlib.sha1()

def xor_string(key, data, encrypt=True):
    if isinstance(key, basestring):
        key = ord(key[0])
    result = []
    iv = 0
    if encrypt:
        for c in data:
            r = (ord(c) ^ iv) ^ key
            result.append(chr(r))
            iv = ord(c)
    else:
        for c in data:
            r = (ord(c) ^ key) ^ iv
            result.append(chr(r))
            iv = r
    return "".join(result)

def get_crypto_time(t = None):
    if t is None:
        return int(time.time())
    now = int(time.time())
    now_t = int(str(now)[-2:])
    if now_t >= t:
        if now_t - t < 48:
            t = int(str(now)[:-2] + ("%0.2d" % (t & 0x7f)))
        else:
            t = int(str(int(str(now)[:-2]) + 1) + ("%0.2d" % (t & 0x7f)))
    else:
        if t - now_t < 48:
            t = int(str(now)[:-2] + ("%0.2d" % (t & 0x7f)))
        else:
            t = int(str(int(str(now)[:-2]) - 1) + ("%0.2d" % (t & 0x7f)))
    return t

def pack_protocel_code(crypto_time, action):
    rand_code = random.randint(0x001, 0xff)
    action_time = (int(str(crypto_time)[-2:]) & 0x7f) | (action << 7)
    protecol_code = (rand_code << 8) | action_time
    return rand_code, struct.pack("!H", protecol_code)

def unpack_protocel_code(protecol_code):
    protecol_code, = struct.unpack("!H", protecol_code)
    rand_code = (protecol_code & 0xff00) >> 8
    action_time = protecol_code & 0xff
    crypto_time = get_crypto_time(action_time & 0x7f)
    return rand_code, ((action_time & 0x80) >> 7), crypto_time

class Crypto(object):
    def __init__(self, key, alg='aes_256_cfb'):
        self._key=key
        self._alg=alg

    def init_encrypt(self, crypto_time, secret=None, session_secret = ""):
        if isinstance(secret, tuple):
            self._ensecret = secret
        else:
            self._ensecret = (secret[:28], secret[28:]) if secret else (rand_string(28), rand_string(16))
        self._encipher = get_evp(
            self._alg,
            self.bytes_to_key(self._ensecret[0] + session_secret, crypto_time, ALG_KEY_IV_LEN.get(self._alg)[0]),
            self.bytes_to_key(self._ensecret[1] + session_secret, crypto_time, ALG_KEY_IV_LEN.get(self._alg)[1]),
            1)
        return  "".join(self._ensecret)

    def init_decrypt(self, crypto_time, secret, session_secret = ""):
        if isinstance(secret, tuple):
            self._ensecret = secret
        else:
            self._desecret= (secret[:28], secret[28:])
        self._decipher = get_evp(
            self._alg,
            self.bytes_to_key(self._desecret[0] + session_secret, crypto_time, ALG_KEY_IV_LEN.get(self._alg)[0]),
            self.bytes_to_key(self._desecret[1] + session_secret, crypto_time, ALG_KEY_IV_LEN.get(self._alg)[1]),
            0)

    def encrypt(self, data):
        return self._encipher.update(data)

    def decrypt(self, data):
        return self._decipher.update(data)

    def bytes_to_key(self, salt, crypto_time, key_len):
        d1, d2 = (self._key.encode('utf-8') if isinstance(self._key, unicode) else self._key), ''
        for i in range(5):
            s = bytes_to_key_digest()
            s.update("".join([d1, salt, str(crypto_time)]))
            d2=d1
            d1=s.digest()
        return (d1+d2)[:key_len]