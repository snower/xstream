# -*- coding: utf-8 -*-
# 14/12/10
# create by: snower

import time
import datetime
import logging
import struct
import socket
import random
from sevent import EventEmitter, current, tcp
from session import Session
from crypto import Crypto, rand_string, xor_string, get_crypto_time, sign_string

class Client(EventEmitter):
    def __init__(self, host, port, max_connections=4, crypto_key='', crypto_alg=''):
        super(Client, self).__init__()

        self._host = host
        self._port = port
        self._max_connections = max_connections
        self._connections = []
        self._session = None
        self._auth_key = None
        self._crypto_key = crypto_key.encode("utf-8") if isinstance(crypto_key, unicode) else crypto_key
        self._crypto_alg = crypto_alg
        self._connecting = None
        self.opening= False
        self.running = False

    def get_auth_key(self):
        return struct.pack("!I", int(time.time())) + rand_string(12)

    def init_connection(self):
        if self._connecting is None and not self._session.closed and len(self._connections) < self._max_connections:
            dt = datetime.datetime.now()
            if dt.second % 20 > 15:
                def do_fork_connection():
                    self._connecting = self.fork_connection()
                current().timeout(20 - (dt.second % 20) + 1, do_fork_connection)
                self._connecting = True
            else:
                self._connecting = self.fork_connection()

    def open(self):
        dt = datetime.datetime.now()
        if dt.second % 20 > 15:
            time.sleep(20 - (dt.second % 20) + 1)

        self.opening = True
        self._connections = []
        self._connecting = None
        self._auth_key = self.get_auth_key()
        connection = tcp.Socket()
        setattr(connection, "is_connected", False)
        setattr(connection, "crypto", Crypto(self._crypto_key, self._crypto_alg))
        connection.connect((self._host, self._port))
        connection.on("connect", self.on_connect)
        connection.on("data", self.on_data)
        connection.on("close", self.on_close)

    def reopen(self, callback=None):
        if callable(callback):
            self.once("session", callback)
        if not self.opening:
            self.open()
        logging.info("xstream client %s session reopen", self)

    def close(self):
        for connection in self._connections:
            connection.close()

    def on_connect(self, connection):
        connection.is_connected = True
        key = connection.crypto.init_encrypt()
        crypto_time = get_crypto_time()
        setattr(connection, "protecol_code", random.randint(0x0000, 0xffff) & 0xff7f)
        setattr(connection, "crypto_time", crypto_time)
        protecol_code = struct.pack("!H", connection.protecol_code)
        protecol_code = xor_string(self._crypto_key[crypto_time % len(self._crypto_key)], protecol_code)
        auth = connection.crypto.encrypt(self._auth_key + sign_string(self._crypto_key + key + self._auth_key + str(crypto_time)))
        connection.write(protecol_code + key + auth + rand_string(random.randint(16, 512)))

    def on_data(self, connection, data):
        self.opening = False
        crypto_time = connection.crypto_time
        protecol_code = connection.protecol_code
        session_id, = struct.unpack("!H", xor_string(self._crypto_key[protecol_code % len(self._crypto_key)], data.read(2), False))
        key = data.read(64)
        connection.crypto.init_decrypt(key)
        auth = connection.crypto.decrypt(data.read(16))
        mss = (connection._socket.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG) or 1460) * 3 - 32
        connection.close()

        if auth == sign_string(self._crypto_key + key + self._auth_key + str(crypto_time)):
            self._session = Session(session_id, self._auth_key, False, connection.crypto, mss)
            self.running = True
            self._session.on("close", self.on_session_close)
            self.emit("session", self, self._session)
            self.init_connection()
            logging.info("xstream client %s session open", self)
            return
        connection.close()
        logging.info("xstream client %s session auth fail", self)

    def on_close(self, connection):
        self.opening = False
        if not connection.is_connected:
            self._session = None
            self.running = False
            logging.info("xstream connection close %s %s", connection, len(self._connections))
        if not self._session:
            current().timeout(1, self.reopen)

    def fork_connection(self):
        connection = tcp.Socket()
        setattr(connection, "crypto", Crypto(self._crypto_key, self._crypto_alg))
        setattr(connection, "is_connected_session", False),
        connection.once("connect", self.on_fork_connect)
        connection.once("close", self.on_fork_close)
        connection.once("data", self.on_fork_data)
        connection.connect((self._host, self._port))
        self._connections.append(connection)
        return connection

    def on_fork_connect(self, connection):
        key = connection.crypto.init_encrypt()
        crypto_time = get_crypto_time()
        setattr(connection, "protecol_code", random.randint(0x0000, 0xffff) | 0x0080)
        setattr(connection, "crypto_time", crypto_time)
        protecol_code = struct.pack("!H", connection.protecol_code)
        protecol_code = xor_string(self._crypto_key[crypto_time % len(self._crypto_key)], protecol_code)
        auth = sign_string(self._crypto_key + key + self._auth_key + str(crypto_time))
        obstruction_len = random.randint(1, 1200)
        obstruction = rand_string(obstruction_len)
        data = self._session._crypto.encrypt(auth + key + struct.pack("!H", obstruction_len))
        connection.write(protecol_code + xor_string(self._crypto_key[connection.protecol_code % len(self._crypto_key)], struct.pack("!H", self._session.id)) + data + obstruction)
        logging.info("xstream connection connect %s", connection)

    def on_fork_data(self, connection, data):
        key_data = self._session._crypto.decrypt(data.read(82))
        crypto_time = connection.crypto_time

        if key_data[:16] == sign_string(self._crypto_key + key_data[16:80] + self._auth_key + str(crypto_time)):
            connection.crypto.init_decrypt(key_data[16:80])
            obstruction_len, = struct.unpack("!H", key_data[80:82])
            data.read(obstruction_len)

            def add_connection():
                self._session.add_connection(connection)
            current().async(add_connection)
            self._connecting = None
            self.init_connection()
            connection.is_connected_session = True
            logging.info("xstream connection ready %s", connection)
            return
        connection.close()
        logging.info("xstream connection auth fail %s", connection)

    def on_fork_close(self, connection):
        self._session.remove_connection(connection)
        if connection in self._connections:
            self._connections.remove(connection)
        if self._connecting == connection:
            self._connecting = None
        if connection.is_connected_session and self.running:
            self.init_connection()
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
            self._session = None
            self.opening = False
            self.running = False
        logging.info("xstream client %s session close", self)
