# _*_ coding: utf_8 _*_
#14_6_20
# create by: snower

import os
import time
import random
import struct

CIPHER_SUITES = [
    0xc02f,
    0x9a9a,
    0x1301,
    0x1302,
    0x1303,
    0xc02b,
    0xc02c,
    0xc030,
    0xcca9,
    0xcca8,
    0xc013,
    0xc014,
    0x009c,
    0x009d,
    0x002f,
    0x0035,
]

ALG_KEY_IV_LEN = {
        'aes_128_cfb': (16, 16),
        'aes_192_cfb': (24, 16),
        'aes_256_cfb': (32, 16),
        'aes_128_gcm': (16, 16),
        'aes_192_gcm': (24, 16),
        'aes_256_gcm': (32, 16),
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

def get_cryptography():
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.hashes import Hash, MD5, SHA1
    from cryptography.hazmat.backends import default_backend
    backend = default_backend()
    buf = bytearray(262144)
    ffi_buf = backend._ffi.cast("unsigned char *", backend._ffi.from_buffer(buf))
    outlen = backend._ffi.new("int *")

    def update_warp(backend, cryptor, buf, ffi_buf, outlen):
        def update(data):
            data_len = len(data)
            if data_len > 261120:
                udata = b''
                for i in range((data_len % 261120) + 1):
                    udata += update(data[i*261120: (i+1) * 261120])
                return udata
            backend._lib.EVP_CipherUpdate(cryptor._ctx._ctx, ffi_buf, outlen, backend._ffi.from_buffer(data), data_len)
            return bytes(buf[:outlen[0]])
        return update

    def get_evp(alg_key, key, iv, op):
        if "aes" not in alg_key:
            return
        cipher = Cipher(algorithms.AES(key), getattr(modes, alg_key.split("_")[-1].upper())(iv), backend=backend)
        cryptor = cipher.encryptor() if op == 1 else cipher.decryptor()
        setattr(cryptor, "update", update_warp(backend, cryptor, buf, ffi_buf, outlen))
        return cryptor

    def rand_string(length):
        return os.urandom(length)

    def sign_string(data):
        d = b''
        for t in (MD5, SHA1, MD5):
            s = Hash(t(), backend=backend)
            s.update(data + d)
            d = s.finalize()
        return d

    def bytes_to_key_digest():
        s = Hash(SHA1(), backend=backend)
        setattr(s, "digest", s.finalize)
        return s

    return get_evp, rand_string, sign_string, bytes_to_key_digest

def get_m2crypto():
    from M2Crypto import Rand,EVP

    def get_evp(alg_key, key, iv, op):
        if alg_key not in ALG_KEY_IV_LEN:
            return
        return EVP.Cipher(alg_key, key, iv, op, 0)

    def rand_string(length):
        return Rand.rand_bytes(length)

    def sign_string(data):
        d = b''
        for t in ("md5", "sha1", "md5"):
            s = EVP.MessageDigest(t)
            s.update(data + d)
            d = s.digest()
        return d

    def bytes_to_key_digest():
        return EVP.MessageDigest('sha1')

    return get_evp, rand_string, sign_string, bytes_to_key_digest

def get_openssl():
    import hashlib
    from .openssl import OpenSSLCrypto

    def get_evp(alg_key, key, iv, op):
        if alg_key not in ALG_KEY_IV_LEN:
            return
        return OpenSSLCrypto(alg_key.replace("_", "-"), key, iv, op)

    def rand_string(length):
        return os.urandom(length)

    def sign_string(data):
        d = b''
        for t in (hashlib.md5, hashlib.sha1, hashlib.md5):
            s = t()
            s.update(data + d)
            d = s.digest()
        return d

    def bytes_to_key_digest():
        return hashlib.sha1()

    return get_evp, rand_string, sign_string, bytes_to_key_digest

if os.environ.get("XSTREAM_CRYPTO", "cryptography").lower() == "cryptography":
    get_evp, rand_string, sign_string, bytes_to_key_digest = get_cryptography()
elif os.environ.get("XSTREAM_CRYPTO", "m2crypto").lower() == "m2crypto":
    get_evp, rand_string, sign_string, bytes_to_key_digest = get_m2crypto()
else:
    get_evp, rand_string, sign_string, bytes_to_key_digest = get_openssl()

def xor_string(key, data, encrypt=True):
    if isinstance(key, str):
        key = ord(key[0])
    result = bytearray()
    iv = 0
    if encrypt:
        for c in data:
            r = (c ^ iv) ^ key
            result.append(r)
            iv = c
    else:
        for c in data:
            r = (c ^ key) ^ iv
            result.append(r)
            iv = r
    return bytes(result)

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
        self._key = key
        self._alg = alg

    def init_encrypt(self, crypto_time, secret=None, session_secret=b""):
        if isinstance(secret, tuple):
            self._ensecret = secret
        else:
            self._ensecret = (secret[:28], secret[28:]) if secret else (rand_string(28), rand_string(16))
        self._encipher = get_evp(
            self._alg,
            self.bytes_to_key(self._ensecret[0] + session_secret, crypto_time, ALG_KEY_IV_LEN.get(self._alg)[0]),
            self.bytes_to_key(self._ensecret[1] + session_secret, crypto_time, ALG_KEY_IV_LEN.get(self._alg)[1]),
            1)
        self.encrypt = self._encipher.update
        return b"".join(self._ensecret)

    def init_decrypt(self, crypto_time, secret, session_secret=b""):
        if isinstance(secret, tuple):
            self._ensecret = secret
        else:
            self._desecret= (secret[:28], secret[28:])
        self._decipher = get_evp(
            self._alg,
            self.bytes_to_key(self._desecret[0] + session_secret, crypto_time, ALG_KEY_IV_LEN.get(self._alg)[0]),
            self.bytes_to_key(self._desecret[1] + session_secret, crypto_time, ALG_KEY_IV_LEN.get(self._alg)[1]),
            0)
        self.decrypt = self._decipher.update

    def encrypt(self, data):
        return self._encipher.update(data)

    def decrypt(self, data):
        return self._decipher.update(data)

    def bytes_to_key(self, salt, crypto_time, key_len):
        crypto_time = str(crypto_time).encode("utf-8")
        key = self._key.encode('utf-8')
        d1, d2 = key, b''
        for i in range(3):
            s = bytes_to_key_digest()
            s.update(b"".join([d1, key, salt, crypto_time]))
            d2, d1 = d1, s.digest()
        return (d1+d2)[:key_len]
