# -*- coding: utf-8 -*-
# 14/12/10
# create by: snower

import os
import time
import logging
import struct
import socket
import random
import hashlib
from sevent import EventEmitter, current, tcp
from session import Session
from crypto import Crypto, rand_string, xor_string, get_crypto_time, sign_string, pack_protocel_code, unpack_protocel_code
from frame import StreamFrame

class Client(EventEmitter):
    def __init__(self, host, port, max_connections=4, crypto_key='', crypto_alg=''):
        super(Client, self).__init__()

        self._host = host
        self._port = port
        self._host_index = 0
        self._max_connections = max_connections
        self._connections = []
        self._session = None
        self._auth_key = None
        self._crypto_key = crypto_key.encode("utf-8") if isinstance(crypto_key, unicode) else crypto_key
        self._crypto_alg = crypto_alg
        self.fork_auth_session_id = rand_string(32)
        self._connecting = None
        self._connecting_time = 0
        self._reconnect_count = 0
        self._fork_auth_fail_count = 0
        self._session_removed = False
        self.opening= False
        self.running = False
        self.init_connection_timeout = 0
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
                with open(session_path + "/" + session_key) as fp:
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
            with open(session_path + "/" + session_key, "w") as fp:
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

    def init_connection(self, is_delay = True, delay_rate = None):
        if not self._session:
            return

        if len(self._connections) >= self._max_connections:
            self.init_connection_timeout = 0
            self.init_connection_delay_rate = 1
            return
        
        def do_init_connection():
            if self._connecting is not None:
                return
            
            if not self._session or self._session.closed or (self._connections and self._session.key_change):
                return
            
            if len(self._connections) >= self._max_connections:
                self.init_connection_timeout = 0
                self.init_connection_delay_rate = 1
                return
            
            self._connecting = self.fork_connection()
            self._connecting_time = time.time()

        if not self._connections:
            do_init_connection()
            self.init_connection_timeout = 0
            self.init_connection_delay_rate = delay_rate or 1
        elif not self._session.key_change and self._connecting is None and \
            (not is_delay or (self.init_connection_timeout > 0 and time.time() >= self.init_connection_timeout)):
            do_init_connection()
            self.init_connection_timeout = 0
        else:
            if delay_rate:
                if delay_rate >= 1:
                    self.init_connection_delay_rate = delay_rate
                elif delay_rate > self.init_connection_delay_rate:
                    delay_rate = self.init_connection_delay_rate
            else:
                delay_rate = self.init_connection_delay_rate
            timeout = time.time() + max(random.randint(90 * (len(self._connections) ** 2), 450 * (len(self._connections) ** 3)) * delay_rate, random.randint(2, 8))
            if self.init_connection_timeout == 0 or timeout < self.init_connection_timeout:
                self.init_connection_timeout = timeout
                self.init_connection_delay_rate = delay_rate

    def on_init_connection_timeout(self, session):
        if not self._session or self._session != session:
            return

        if self.init_connection_timeout > 0 and time.time() >= self.init_connection_timeout:
            self.init_connection()
        elif len(self._session._connections) == 1:
            conn = self._session._connections[0]
            if conn and conn._rdata_count and conn._rdata_count > 1048576 and conn._expried_data and time.time() - conn._start_time > 5:
                delay_rate = min(1.0 / ((float(conn._rdata_count) / 1048576.0)  ** 10 / (float(conn._expried_data) / 1048576.0)), 1)
                if delay_rate < self.init_connection_delay_rate:
                    self.init_connection(True, delay_rate)
        current().timeout(5, self.on_init_connection_timeout, self._session)

    def open(self):
        session = self.load_session()
        if session:
            self._session = session
            self._session.on("close", self.on_session_close)
            self._session.on("keychange", lambda session: self.save_session())
            self.emit("session", self, self._session)

            self.running = True
            self.init_connection(False)
            current().timeout(5, self.on_init_connection_timeout, self._session)
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
        current().timeout(5, on_timeout)

    def reopen(self, callback=None):
        if callable(callback):
            self.once("session", callback)
        if not self.opening:
            def do_open():
                if not self.opening and not self.running:
                    self.open()
                    logging.info("xstream client %s session reopen", self)
            current().timeout(2, do_open)

    def close(self):
        for connection in self._connections:
            connection.close()

    def on_connect(self, connection):
        connection.is_connected = True
        crypto_time = int(time.time())
        key = connection.crypto.init_encrypt(crypto_time)
        auth_key = connection.crypto.encrypt(self._auth_key)
        auth = sign_string(self._crypto_key + key + self._auth_key + str(crypto_time))
        data = "".join(['\x03\x03', struct.pack("!I", crypto_time), key[:28], '\x20', auth_key, key[28:], struct.pack("!H", len(auth)), auth, '\x01\x00\x00'])
        connection.write("".join(['\x16\x03\x01', struct.pack("!H", len(data) + 4), '\x01\x00', struct.pack("!H", len(data)), data]))
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
        if auth == sign_string(self._crypto_key + key + self._auth_key + str(crypto_time)):
            self._session = Session(session_id, self._auth_key, False, connection.crypto, StreamFrame.FRAME_LEN)
            self._session.on("close", self.on_session_close)
            self._session.on("keychange", lambda session: self.save_session())
            self.emit("session", self, self._session)

            self.running = True
            self.init_connection(False)
            connection.close()
            self._session_removed = False
            self.save_session()
            self._session.write_action(0x01)
            current().timeout(5, self.on_init_connection_timeout, self._session)
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
            current().timeout(1, self.reopen)
        logging.info("xstream auth connection close %s %s", connection, len(self._connections))

    def fork_connection(self):
        connection = tcp.Socket()
        connection.enable_nodelay()
        setattr(connection, "crypto", Crypto(self._crypto_key, self._crypto_alg))
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
        current().timeout(5, on_timeout)
        return connection

    def on_fork_connect(self, connection):
        if not self._session:
            return connection.close()

        crypto_time = int(time.time())
        session_id = xor_string(crypto_time & 0xff, struct.pack("!H", self._session.id))

        key = connection.crypto.init_encrypt(crypto_time)
        auth = sign_string(self._crypto_key + key + self._auth_key + str(crypto_time))

        crypto = self._session.get_encrypt_crypto(crypto_time)
        key = crypto.encrypt(key)

        data = "".join(['\x00\x23\x00\xc0', auth, key[28:], rand_string(160), '\x00\x05\x00\x05\x01\x00\x00\x00\x00', '\x00\x10\x00\x05\x00\x03\x02\x68\x32'])

        ciphres = "".join(
            [session_id, '\xc0\x2b', '\xc0\x2c', '\xc0\x2f', '\xc0\x30', '\xcc\xa9', '\xcc\xa8', '\xc0\x13', '\xc0\x14',
             '\x00\x9c', '\x00\x9d', '\x00\x2f', '\x00\x35', '\x00\x0a'])

        data = "".join(['\x03\x03', struct.pack("!I", crypto_time), key[:28], '\x20', self.fork_auth_session_id,
                        struct.pack("!H", len(ciphres)), ciphres, '\x01\x00', struct.pack("!H", len(data)), data])

        connection.write(
            "".join(['\x16\x03\x03', struct.pack("!H", len(data) + 4), '\x01\x00', struct.pack("!H", len(data)), data]))

        logging.info("xstream connection connect %s", connection)

    def on_fork_data(self, connection, data):
        try:
            data.read(11)
            crypto_time, = struct.unpack("!I", data.read(4))
            key = data.read(28)
            data.read(36)
            extensions_len, = struct.unpack("!H", data.read(2))
            data.read(extensions_len)

            last_data = str(data)
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

        if auth == sign_string(self._crypto_key + key + self._auth_key + str(crypto_time)):
            self._session.set_last_auth_time(crypto_time)
            setattr(connection, "crypto_time", crypto_time)
            connection.crypto.init_decrypt(crypto_time, key)

            connection.write("".join(['\x14\x03\x03\x00\x01\x01', '\x16\x03\x03\x00\x28', rand_string(40)]))

            def add_connection(conn):
                connection = self._session.add_connection(conn)
                if not connection:
                    conn.close()
                else:
                    connection.write_action(0x05, rand_string(random.randint(128, 256)))
                    connection.start()
                    def on_expried(is_close = False):
                        if not is_close and len(self._connections) <= 1:
                            self.init_connection(False)
                            current().timeout(5, on_expried, True)
                        else:
                            connection.on_expried()
                    current().timeout(connection._expried_seconds, on_expried)
                    current().timeout(30, connection.on_ping_loop)

            current().async(add_connection, connection)
            self._connecting = None
            self._reconnect_count = 0
            if len(self._connections) >= 2:
                self._session.start_key_change()
            self.init_connection()
            connection.is_connected_session = True
            logging.info("xstream connection ready %s", connection)
            self._fork_auth_fail_count = 0
            return
        connection.close()
        logging.info("xstream connection auth fail %s %s %s", connection, time.time(), crypto_time)
        self._fork_auth_fail_count += 1
        if self._fork_auth_fail_count >= 3:
            self.remove_session()
            if self._session:
                self._session.close()

    def on_fork_close(self, connection):
        if not self._session:
            return
        conn = self._session.remove_connection(connection)
        if connection in self._connections:
            self._connections.remove(connection)
        if self._connecting == connection:
            self._connecting = None
        if self.running:
            if connection.is_connected_session:
                current().async(self.init_connection)
            elif self._reconnect_count < 60:
                self._reconnect_count += 1
                if conn and conn._rdata_count and conn._expried_data and time.time() - conn._start_time > 5:
                    delay_rate = min(1.0 / ((float(conn._rdata_count) / 1048576.0)  ** 10 / (float(conn._expried_data) / 1048576.0)), 1)
                else:
                    delay_rate = 1
                current().timeout(self._reconnect_count, self.init_connection, True, delay_rate)
            else:
                self._session.close()
        logging.info("xstream connection close %s %s", connection, len(self._connections))

    def session(self, callback=None):
        if self._session is None:
            self.reopen(callback)
        elif callable(callback):
            if not self._connections:
                self.init_connection()
            callback(self, self._session)
        return self._session

    def on_session_close(self, session):
        if self._session == session:
            self.save_session()
            self._session = None
            self._connections = []
            self._connecting = None
            self._reconnect_count = 0
            self.opening = False
            self.running = False
        logging.info("xstream client %s session close", self)
