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
        self._connecting = None
        self._reconnect_count = 0
        self.opening= False
        self.running = False

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
        session_path = self.get_session_path()
        if not os.path.exists(session_path + "/"):
            os.makedirs(session_path + "/")
        session_key = self.get_session_key()
        session = self._session.dumps()
        with open(session_path + "/" + session_key, "w") as fp:
            fp.write(session)
        self.init_connection()

    def init_connection(self, is_delay = True):
        if not self._session:
            return

        if self._session.key_change:
            return
        
        def do_init_connection():
            if self._connecting is not None:
                return
            
            if not self._session or self._session.closed or self._session.key_change:
                return
            
            if len(self._connections) >= self._max_connections:
                return
            
            self._connecting = self.fork_connection()

        if not is_delay or not self._connections:
            do_init_connection()
        elif len(self._connections) >= 1:
            current().timeout(random.randint(5 * (len(self._connections) ** 2), 60 * (len(self._connections) ** 2)), do_init_connection)

    def open(self):
        session = self.load_session()
        if session:
            self._session = session
            self._session.on("close", self.on_session_close)
            self._session.on("keychange", lambda session: self.save_session())
            self.emit("session", self, self._session)

            self.running = True
            self.init_connection(False)
            self._session.write_action(0x01)
            logging.info("xstream client %s session open", self)
            return

        self.opening = True
        self._connections = []
        self._connecting = None
        self._auth_key = self.get_auth_key()
        connection = tcp.Socket()
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
        crypto_time = get_crypto_time()
        _, protecol_code = pack_protocel_code(crypto_time, 0)
        key = connection.crypto.init_encrypt(crypto_time)
        auth = connection.crypto.encrypt(self._auth_key + sign_string(self._crypto_key + key + self._auth_key + str(crypto_time)))
        connection.write(protecol_code + key + auth + rand_string(random.randint(16, 1024)))
        logging.info("xstream auth connection connect %s", connection)

    def on_data(self, connection, data):
        self.opening = False
        rand_code, action, crypto_time = unpack_protocel_code(data.read(2))
        session_id, = struct.unpack("!H", xor_string(rand_code & 0xff, data.read(2), False))
        key = data.read(64)
        connection.crypto.init_decrypt(crypto_time, key)
        auth = connection.crypto.decrypt(data.read(16))

        if auth == sign_string(self._crypto_key + key + self._auth_key + str(crypto_time)):
            try:
                mss = min((connection._socket.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG) or 1460) * 2 - 20, StreamFrame.FRAME_LEN)
            except:
                mss = StreamFrame.FRAME_LEN
            self._session = Session(session_id, self._auth_key, False, connection.crypto, mss)
            self._session.on("close", self.on_session_close)
            self._session.on("keychange", lambda session: self.save_session())
            self.emit("session", self, self._session)

            self.running = True
            self.init_connection(False)
            connection.close()
            self.save_session()
            self._session.write_action(0x01)
            logging.info("xstream client %s session open", self)
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

        crypto_time = get_crypto_time()
        rand_code, protecol_code = pack_protocel_code(crypto_time, 1)
        session_id = xor_string(rand_code & 0xff, struct.pack("!H", self._session.id))

        key = connection.crypto.init_encrypt(crypto_time)
        auth = sign_string(self._crypto_key + key + self._auth_key + str(crypto_time))
        obstruction_len = random.randint(16, 1024)
        obstruction = rand_string(obstruction_len)

        crypto = self._session.get_encrypt_crypto(crypto_time)
        data = crypto.encrypt(auth + key + struct.pack("!H", obstruction_len))

        connection.write(protecol_code + session_id + data + obstruction)
        logging.info("xstream connection connect %s", connection)

    def on_fork_data(self, connection, data):
        rand_code, action, crypto_time = unpack_protocel_code(data.read(2))
        crypto = self._session.get_decrypt_crypto(crypto_time)
        decrypt_data = crypto.decrypt(data.read(82))

        key = decrypt_data[16:80]
        if decrypt_data[:16] == sign_string(self._crypto_key + key + self._auth_key + str(crypto_time)):
            try:
                self._session._mss = min((connection._socket.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG) or 1460) * 2 - 20, StreamFrame.FRAME_LEN)
            except:pass
            setattr(connection, "crypto_time", crypto_time)
            connection.crypto.init_decrypt(crypto_time, key)
            obstruction_len, = struct.unpack("!H", decrypt_data[80:82])
            data.read(obstruction_len)

            def add_connection(conn):
                connection = self._session.add_connection(conn)
                if not connection:
                    conn.close()
                else:
                    def on_expried(is_close = False):
                        if not is_close and len(self._connections) <= 1:
                            self.init_connection(False)
                            current().timeout(5, on_expried, True)
                        else:
                            connection.on_expried()
                    current().timeout(random.randint(180, 1800), on_expried)
                    current().timeout(30, connection.on_ping_loop)

            current().async(add_connection, connection)
            self._connecting = None
            self._reconnect_count = 0
            if len(self._connections) >= 2:
                self._session.start_key_change()
            else:
                self.init_connection()
            connection.is_connected_session = True
            logging.info("xstream connection ready %s", connection)
            return
        connection.close()
        logging.info("xstream connection auth fail %s %s %s", connection, time.time(), crypto_time)

    def on_fork_close(self, connection):
        if not self._session:
            return
        self._session.remove_connection(connection)
        if connection in self._connections:
            self._connections.remove(connection)
        if self._connecting == connection:
            self._connecting = None
        if self.running:
            if connection.is_connected_session:
                current().async(self.init_connection)
            elif self._reconnect_count < 60:
                self._reconnect_count += 1
                current().timeout(self._reconnect_count, self.init_connection)
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
