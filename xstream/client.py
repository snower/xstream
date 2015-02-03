# -*- coding: utf-8 -*-
# 14/12/10
# create by: snower

import time
import logging
import struct
from sevent import EventEmitter, current, tcp
from session import Session
from crypto import Crypto, rand_string

class Client(EventEmitter):
    def __init__(self, host, port, max_connections=4, crypto_key='', crypto_alg=''):
        super(Client, self).__init__()

        self._host = host
        self._port = port
        self._max_connections = max_connections
        self._connections = []
        self._session = None
        self._auth_key = None
        self._crypto_key = crypto_key
        self._crypto_alg = crypto_alg
        self._connecting = None
        self.opening= False
        self.running = False

    def get_auth_key(self):
        return struct.pack("!I", int(time.time())) + rand_string(12)

    def init_connection(self):
        if self._connecting is None and len(self._connections) < self._max_connections:
            self._connecting = self.fork_connection()

    def open(self):
        self.opening = True
        self._auth_key = self.get_auth_key()
        connection = tcp.Socket()
        setattr(connection, "crypto", Crypto(self._crypto_key, self._crypto_alg))
        connection.connect((self._host, self._port))
        connection.on("connect", self.on_connect)
        connection.on("data", self.on_data)

    def reopen(self, callback=None):
        if callable(callback):
            self.once("session", callback)
        if not self.opening:
            self.open()

    def close(self):
        for connection in self._connections:
            connection.close()

    def on_connect(self, connection):
        key = connection.crypto.init_encrypt()
        connection.write('\x00' + self._auth_key + key)

    def on_data(self, connection, data):
        session_id, = struct.unpack("!H", data.read(2))
        connection.crypto.init_decrypt(data.read(64))
        self._session = Session(session_id, self._auth_key, False, connection.crypto)
        connection.close()

        self.opening = False
        self.running = True
        self.emit("session", self, self._session)
        self._session.on("sleeping", self.on_session_sleeping)
        self._session.on("wakeup", self.on_session_wakeup)
        self._session.on("suspend", self.on_session_suspend)
        self.init_connection()

    def fork_connection(self):
        connection = tcp.Socket()
        setattr(connection, "crypto", Crypto(self._crypto_key, self._crypto_alg))
        setattr(connection, "is_connected_session", False),
        connection.connect((self._host, self._port))
        connection.once("connect", self.on_fork_connect)
        connection.once("close", self.on_fork_close)
        connection.once("data", self.on_fork_data)
        self._connections.append(connection)
        return connection

    def on_fork_connect(self, connection):
        key = connection.crypto.init_encrypt()
        data = self._session._crypto.encrypt(self._session.auth_key + key)
        connection.write('\x01' + struct.pack("!H", self._session.id) + data)
        logging.info("connection connect %s", connection)

    def on_fork_data(self, connection, data):
        key = self._session._crypto.decrypt(data.read(64))
        connection.crypto.init_decrypt(key)
        def add_connection():
            self._session.add_connection(connection)
        current().sync(add_connection)
        self._connecting = None
        self.init_connection()
        connection.is_connected_session = True
        logging.info("connection ready %s", connection)

    def on_fork_close(self, connection):
        self._session.remove_connection(connection)
        if connection in self._connections:
            self._connections.remove(connection)
        if self._connecting == connection:
            self._connecting = None
        if connection.is_connected_session and self.running:
            current().timeout(1, self.init_connection)
        logging.info("connection close %s", connection)

    def session(self, callback=None):
        if self._session is None:
            self.reopen(callback)
        elif callable(callback):
            if not self._connections:
                self.init_connection()
            callback(self, self._session)
        return self._session

    def on_session_suspend(self, session):
        def on_suspend():
            if not self._connections and not self._connecting:
                self._session.close()
                self._session = None
                self.opening = False
                self.running = False
        current().timeout(2, on_suspend)

    def on_session_sleeping(self, session):
        self.running = False

    def on_session_wakeup(self, session):
        self.running = True
        self.init_connection()
