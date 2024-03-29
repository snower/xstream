# -*- coding: utf-8 -*-
# 14/12/10
# create by: snower

import os
import time
import logging
import struct
import math
import random
import hashlib
from sevent import EventEmitter, current, tcp
from .session import Session
from .crypto import Crypto, rand_string, xor_string, sign_string, CIPHER_SUITES
from .frame import StreamFrame

class Client(EventEmitter):
    def __init__(self, host, port, max_connections=4, crypto_key='', crypto_alg='', session_id=0):
        super(Client, self).__init__()

        self._host = host
        self._port = port
        self._host_index = 0
        self._max_connections = max_connections
        self._connections = []
        self._init_session_id = session_id
        self._session = None
        self._auth_key = None
        self._crypto_key = crypto_key
        self._crypto_alg = crypto_alg
        self.fork_auth_session_id = rand_string(32)
        self._connecting = None
        self._connecting_time = 0
        self._reconnect_count = 0
        self._fork_auth_fail_count = 0
        self._session_removed = False
        self.opening= False
        self.running = False

        self.init_connection_timeout = None
        self.init_connection_timeout_handler = None
        self.init_connection_delay_rate = 1

    def get_auth_key(self):
        return struct.pack("!I", int(time.time())) + rand_string(12)

    def get_session_key(self):
        return hashlib.md5("".join([str(self._host), str(self._port), self._crypto_key, self._crypto_alg]).encode("utf-8")).hexdigest()

    def get_session_path(self):
        session_path = os.environ.get("SESSION_PATH")
        if session_path:
            return os.path.abspath(session_path)
        return os.path.abspath("./session")

    def load_session(self):
        if self._session_removed:
            return None
        
        session_path = self.get_session_path()
        if not os.path.exists(session_path + "/"):
            os.makedirs(session_path + "/")
        session_key = self.get_session_key()

        try:
            if os.path.exists(session_path + "/" + session_key):
                with open(session_path + "/" + session_key, encoding="utf-8") as fp:
                    session = Session.loads(fp.read())
                    if session:
                        self._auth_key = session.auth_key
                        logging.info("xstream load session %s %s %s", self, session_key, session)
                        return session
        except Exception as e:
            logging.error("xstream load session fail %s %s", self, session_key)
        return None

    def save_session(self):
        if self._session_removed:
            return
        
        session_path = self.get_session_path()
        if not os.path.exists(session_path + "/"):
            os.makedirs(session_path + "/")
        session_key = self.get_session_key()
        session = self._session.dumps()
        if session:
            with open(session_path + "/" + session_key, "w", encoding="utf-8") as fp:
                fp.write(session)
            self.init_connection()
            logging.info("xstream save session %s %s %s", self, session_key, self._session)
        
    def remove_session(self):
        session_path = self.get_session_path()
        if not os.path.exists(session_path + "/"):
            os.makedirs(session_path + "/")
        session_key = self.get_session_key()
        try:
            os.remove(session_path + "/" + session_key)
        except OSError:
            pass
        self._session_removed = True
        logging.info("xstream remove session %s %s %s", self, session_key, self._session)

    def init_connection(self, is_delay = True, delay_rate = None, connect_next = False):
        if not self._session or self._session.closed:
            return

        if self._connecting is not None:
            return

        if len(self._connections) >= self._max_connections:
            if self.init_connection_timeout_handler:
                current().cancel_timeout(self.init_connection_timeout_handler)
                self.init_connection_timeout_handler = None
            self.init_connection_timeout = None
            self.init_connection_delay_rate = 1
            return
        
        def do_init_connection():
            if self._connecting is not None:
                return

            if self.init_connection_timeout_handler:
                current().cancel_timeout(self.init_connection_timeout_handler)
                self.init_connection_timeout_handler = None
            self.init_connection_timeout = None
            self.init_connection_delay_rate = 1
            
            if not self._session or self._session.closed \
                    or (self._connections and not self._session.key_exchanged):
                return
            
            if len(self._connections) >= self._max_connections:
                return
            
            self._connecting = self.fork_connection()
            self._connecting_time = time.time()

        if not self._connections:
            do_init_connection()
        elif self._session.key_exchanged and not is_delay:
            do_init_connection()
        else:
            if delay_rate:
                if delay_rate > self.init_connection_delay_rate:
                    delay_rate = self.init_connection_delay_rate
            else:
                delay_rate = self.init_connection_delay_rate

            timeout = max(random.randint(1200 * len(self._connections), 3600 * len(self._connections)) * delay_rate, random.randint(0, 3))

            if self.init_connection_timeout_handler:
                current().cancel_timeout(self.init_connection_timeout_handler)
            self.init_connection_timeout = time.time() + timeout
            self.init_connection_timeout_handler = current().add_timeout(timeout, do_init_connection)

            if connect_next:
                self.init_connection_delay_rate = delay_rate
            else:
                self.init_connection_delay_rate = 1

    def on_init_connection_timeout(self, session, last_rdata_lens):
        if not self._session or self._session != session:
            return

        if len(self._session._connections) >= self._max_connections:
            current().add_timeout(5, self.on_init_connection_timeout, self._session, {})
            return

        rdata_counts, rdata_count = {}, 0
        for conn in self._session._connections:
            rdata_count += conn._rdata_len + conn._wdata_len - last_rdata_lens.get(id(conn), 0)
            rdata_counts[id(conn)] = conn._rdata_len + conn._wdata_len

        if last_rdata_lens:
            if rdata_count > len(self._session._connections) * 1310720:
                self.init_connection(False)
            elif self._session._center.ttl >= len(self._session._connections) * 720:
                self.init_connection(False)

        current().add_timeout(5, self.on_init_connection_timeout, self._session, rdata_counts)

    def open(self):
        session = self.load_session()
        if session:
            self._session = session
            self._session.on("close", self.on_session_close)
            self._session.on("keyexchange", lambda session: self.save_session())
            self.emit_session(self, self._session)

            self.running = True
            self.init_connection(False)
            current().add_timeout(5, self.on_init_connection_timeout, self._session, {})
            self._session.write_action(0x01)
            logging.info("xstream client %s session open", self)
            return

        self.opening = True
        self._connections = []
        self._connecting = None
        self._auth_key = self.get_auth_key()
        connection = tcp.Socket()
        connection.enable_nodelay()
        setattr(connection, "is_connected", False)
        setattr(connection, "crypto", Crypto(self._crypto_key, self._crypto_alg))
        connection.on("connect", self.on_connect)
        connection.on("data", self.on_data)
        connection.on("close", self.on_close)
        if isinstance(self._host, (tuple, list, set)):
            connection.connect(tuple(self._host[0]))
        else:
            connection.connect((self._host, self._port))
        
        def on_timeout():
            connection.close()
        current().add_timeout(5, on_timeout)

    def reopen(self, callback=None):
        if callable(callback):
            self.once("session", callback)
        if not self.opening:
            def do_open():
                if not self.opening and not self.running:
                    self.open()
                    logging.info("xstream client %s session reopen", self)
            current().add_timeout(2, do_open)

    def close(self):
        for connection in self._connections:
            connection.close()

    def on_connect(self, connection):
        connection.is_connected = True
        crypto_time = int(time.time())
        key = connection.crypto.init_encrypt(crypto_time)
        auth_key = connection.crypto.encrypt(self._auth_key)
        auth = sign_string(self._crypto_key.encode("utf-8") + key + self._auth_key + str(crypto_time).encode("utf-8"))
        data = b"".join([struct.pack("!H", self._init_session_id) if self._init_session_id else b'\x03\x03', struct.pack("!I", crypto_time),
                         key[:28], b'\x20', auth_key, key[28:], struct.pack("!H", len(auth)), auth, b'\x01\x00\x00'])
        connection.write(b"".join([b'\x16\x03\x01', struct.pack("!H", len(data) + 4), b'\x01\x00', struct.pack("!H", len(data)), data]))
        logging.info("xstream auth connection connect %s", connection)

    def on_data(self, connection, data):
        data.read(11)
        crypto_time, = struct.unpack("!I", data.read(4))
        key = data.read(28)
        data.read(1)
        auth = data.read(16)
        key += data.read(16)
        session_id, = struct.unpack("!H", xor_string(crypto_time & 0xff, data.read(2), False))
        data.read(2)

        self.opening = False
        connection.crypto.init_decrypt(crypto_time, key)
        auth = connection.crypto.decrypt(auth)
        if auth == sign_string(self._crypto_key.encode("utf-8") + key + self._auth_key + str(crypto_time).encode("utf-8")):
            self._session = Session(session_id, self._auth_key, False, connection.crypto, StreamFrame.FRAME_LEN)
            self._session.on("close", self.on_session_close)
            self._session.on("keyexchange", lambda session: self.save_session())
            self.emit_session(self, self._session)

            self.running = True
            self.init_connection(False)
            connection.close()
            self._session_removed = False
            self.save_session()
            self._session.write_action(0x01)
            current().add_timeout(5, self.on_init_connection_timeout, self._session, {})
            logging.info("xstream client %s session %s open", self, self._session)
            return
        connection.close()
        logging.info("xstream client %s session auth fail %s %s", self, time.time(), crypto_time)

    def on_close(self, connection):
        self.opening = False
        if not connection.is_connected:
            self._session = None
            self.running = False
        if not self._session:
            current().add_timeout(1, self.reopen)
        logging.info("xstream auth connection close %s %s", connection, len(self._connections))

    def fork_connection(self):
        connection = tcp.Socket()
        connection.enable_nodelay()
        setattr(connection, "crypto", Crypto(self._crypto_key, self._crypto_alg))
        setattr(connection, "is_connected_xstream", False),
        setattr(connection, "is_connected_session", False),
        connection.once("connect", self.on_fork_connect)
        connection.once("close", self.on_fork_close)
        connection.once("data", self.on_fork_data)
        if isinstance(self._host, (tuple, list, set)):
            connection.connect(tuple(self._host[self._host_index]))
            self._host_index += 1
            if self._host_index >= len(self._host):
                self._host_index = 0
        else:
            connection.connect((self._host, self._port))
        self._connections.append(connection)
        
        def on_timeout():
            if not connection.is_connected_session:
                connection.close()
        current().add_timeout(15, on_timeout)
        return connection

    def on_fork_connect(self, connection):
        if not self._session:
            return connection.close()

        crypto_time = int(time.time())
        cipher_suites = {cs: True for cs in CIPHER_SUITES}
        session_id = self._session.id
        rcipher_suites = [struct.pack("!H", session_id)]
        while cipher_suites:
            cs = random.choice(list(cipher_suites.keys()))
            cipher_suites.pop(cs)
            if cs == session_id:
                continue
            rcipher_suites.append(struct.pack("!H", cs))
        ciphres = b"".join(rcipher_suites)

        key = connection.crypto.init_encrypt(crypto_time)
        auth = sign_string(self._crypto_key.encode("utf-8") + key + self._auth_key + str(crypto_time).encode("utf-8"))

        crypto = self._session.get_encrypt_crypto(crypto_time)
        key = crypto.encrypt(key)

        data = b"".join([b'\x00\x23\x00\xb0', auth, key[28:], rand_string(144),
                         b'\x00\x0b\x00\x04\x03\x00\x01\x02',
                         b'\x00\x16\x00\x00', b'\x00\x17\x00\x00',
                         b'\x00\x10\x00\x0e\x00\x0c\x02\x68\x32\x08\x68\x74\x74\x70\x2f\x31\x2e\x31',
                         b'\x00\x2d\x00\x02\x01\x01'])

        data = b"".join([b'\x03\x03', struct.pack("!I", crypto_time), key[:28], b'\x20', self.fork_auth_session_id,
                        struct.pack("!H", len(ciphres)), ciphres, b'\x01\x00', struct.pack("!H", len(data)), data])

        connection.write(b"".join([b'\x16\x03\x03', struct.pack("!H", len(data) + 4), b'\x01\x00', struct.pack("!H", len(data)), data]))
        connection.is_connected_xstream = True
        logging.info("xstream connection connect %s", connection)

    def on_fork_data(self, connection, data):
        try:
            data.read(11)
            crypto_time, = struct.unpack("!I", data.read(4))
            key = data.read(28)
            data.read(36)
            extensions_len, = struct.unpack("!H", data.read(2))
            data.read(extensions_len)

            last_data = b''.join([b'', data.join()])
            auth = last_data[11:27]
            key += last_data[27:43]

            if not (crypto_time, key, auth):
                connection.close()
                self.remove_session()
                if self._session:
                    self._session.close()
                return
        except:
            connection.close()
            self.remove_session()
            if self._session:
                self._session.close()
            return

        crypto = self._session.get_decrypt_crypto(crypto_time)
        key = crypto.decrypt(key)

        if auth == sign_string(self._crypto_key.encode("utf-8") + key + self._auth_key + str(crypto_time).encode("utf-8")):
            if key in self._session._auth_cache:
                logging.info("xstream connection auth reuse session closed %s %s", connection, time.time())
                connection.close()
                return
            self._session._auth_cache[key] = time.time()

            self._session.set_last_auth_time(crypto_time)
            setattr(connection, "crypto_time", crypto_time)
            connection.crypto.init_decrypt(crypto_time, key)

            connection.write(b"".join([b'\x14\x03\x03\x00\x01\x01', b'\x16\x03\x03\x00\x28', rand_string(40)]))

            def add_connection(conn):
                connection = self._session.add_connection(conn)
                if not connection:
                    conn.close()
                    return

                current().add_async(connection.on_ping_loop)
                def on_expried(is_close=False):
                    if self._session and not self._session.key_exchanged and len(self._connections) <= 1:
                        current().add_timeout(random.randint(5, 15), on_expried)
                    elif not is_close and len(self._connections) <= 1:
                        self.init_connection(False)
                        current().add_timeout(random.randint(5, 15), on_expried, True)
                    else:
                        connection.on_expried()
                connection._expried_seconds_timer = current().add_timeout(connection._expried_seconds, on_expried)
                connection._expried_data_timer = current().add_timeout(15, connection.on_check_data_loop)

            current().add_async(add_connection, connection)
            self._connecting = None
            self._reconnect_count = 0
            self.init_connection()
            connection.is_connected_session = True
            self.fork_auth_session_id = rand_string(32)
            logging.info("xstream connection ready %s %s:%s", connection, connection.address[0], connection.address[1])
            self._fork_auth_fail_count = 0
            return

        connection.close()
        logging.info("xstream connection auth fail %s %s %s %s:%s", connection, time.time(), crypto_time, connection.address[0], connection.address[1])

    def on_fork_close(self, connection):
        if not self._session:
            return

        conn = self._session.remove_connection(connection)
        if connection in self._connections:
            self._connections.remove(connection)
        if self._connecting == connection:
            self._connecting = None

        if connection.is_connected_xstream and not connection.is_connected_session and not self._connections:
            self._fork_auth_fail_count += 1
            if self._fork_auth_fail_count > 8:
                self.remove_session()
                if self._session:
                    self._session.close()
                logging.info("xstream session reauth %s %s", connection, self._session)
                logging.info("xstream connection close %s %s", connection, len(self._connections))
                return

        if self.running:
            if connection.is_connected_session:
                delay_rate, connect_next = 1, False
                if conn and conn._rdata_len and conn._expried_data:
                    etime = time.time() - conn._start_time
                    rdata_count = float(conn._rdata_len) / etime * 180.0
                    try:
                        if etime < conn._expried_seconds / 2.0:
                            delay_rate = max(min((12 - math.exp((float(rdata_count * 2) / float(16777216) + 1) ** 4)) / 10.0, 1), 0.001)
                        else:
                            delay_rate = max(min((12 - math.exp((float(rdata_count) / float(16777216) + 1) ** 4)) / 10.0, 1), 0.001)
                    except OverflowError:
                        delay_rate = 0.001
                    except:
                        delay_rate = 1
                    if etime < conn._expried_seconds / 2.0 or conn._rdata_len > conn._expried_data * 2:
                        connect_next = True
                current().add_async(self.init_connection, True, delay_rate, connect_next)
                logging.info("xstream connection close init_connection %s %s %s", len(self._connections), delay_rate, connect_next)
            elif not connection.is_connected_xstream and self._reconnect_count < 30:
                self._reconnect_count += 1
                if isinstance(self._host, (tuple, list, set)):
                    current().add_timeout(10 if self._reconnect_count >= len(self._host) else 1, self.init_connection, False)
                else :
                    current().add_timeout(10, self.init_connection, False)
                logging.info("xstream connection connect error reinit_connection %s %s", len(self._connections), self._reconnect_count)
            elif self._reconnect_count < 30:
                self._reconnect_count += 1
                current().add_timeout(self._reconnect_count, self.init_connection, False)
                logging.info("xstream connection close reinit_connection %s %s", len(self._connections), self._reconnect_count)
            else:
                self._session.close()
        logging.info("xstream connection close %s %s", connection, len(self._connections))

    def session(self, callback=None):
        if self._session is None:
            self.reopen(callback)
        elif callable(callback):
            if not self._connections:
                self.init_connection(False)
            callback(self, self._session)
        return self._session

    def on_session_close(self, session):
        if self._session == session:
            self.save_session()
            self._session = None
            self._connections = []
            self._connecting = None
            self.opening = False
            self.running = False
            self.init_connection_timeout = None
            self.init_connection_timeout_handler = None
            self.init_connection_delay_rate = 1
        logging.info("xstream client %s session close", self)
