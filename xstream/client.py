# -*- coding: utf-8 -*-
# 14/12/10
# create by: snower

import logging
import struct
from ssloop import EventEmitter, Socket, current
from session import Session
from crypto import Crypto

class Client(EventEmitter):
    def __init__(self, host, port, max_connections=4, crypto_key='', crypto_alg=''):
        super(Client, self).__init__()

        self._host = host
        self._port = port
        self._max_connections = max_connections
        self._connections = []
        self._session = None
        self._crypto_key = crypto_key
        self._crypto_alg = crypto_alg
        self._crypto = Crypto(self.crypto_key, self.crypto_alg)
        self._connecting = None
        self.opening= False
        self.running = False

    def init_connection(self):
        if self._connecting is None and len(self._connections) < self._max_connections:
            self._connecting = self.fork_connection()

    def open(self):
        self.opening = True
        connection = Socket()
        connection.connect((self._host, self._port))
        connection.on("connect", self.on_connect)

    def reopen(self, callback=None):
        if callable(callback):
            self.once("session", callback)
        if not self.opening:
            self.open()

    def close(self):
        for connection in self._connections:
            connection.close()

    def on_connect(self, connection):
        key = self._crypto.init_encrypt()
        connection.write('\x00'+key)
        connection.on("data", self.on_data)

    def on_data(self, connection, data):
        session_id, = struct.unpack("!H", data[:2])
        self._crypto.init_decrypt(data[2:])
        self._session = Session(session_id)
        connection.close()
        self.opening = False
        self.running = True
        self.emit("session", self, self._session)
        self._session.on("sleeping", self.on_session_sleeping)
        self._session.on("wakeup", self.on_session_wakeup)
        self._session.on("suspend", self.on_session_suspend)
        self.init_connection()

    def fork_connection(self):
        connection = Socket()
        setattr(connection, "crypto", Crypto(self.crypto_key, self.crypto_alg))
        connection.connect((self._host, self._port))
        connection.once("connect", self.on_fork_connect)
        self._connections.append(connection)
        return connection

    def on_fork_connect(self, connection):
        key = connection.crypto.init_encrypt()
        data = self._crypto.encrypt(struct.pack("!H", self._session.id) + key)
        connection.write('\x01' + data)
        connection.once("data", self.on_fork_data)
        connection.once("close", self.on_fork_close)
        logging.info("connection connect %s", connection)

    def on_fork_data(self, connection, data):
        key = self._crypto.decrypt(data)
        connection.crypto.init_decrypt(key)
        self._session.add_connection(connection)
        self._connecting = None
        self.init_connection()
        logging.info("connection ready %s", connection)

    def on_fork_close(self, connection):
        self._session.remove_connection(connection)
        if connection in self._connections:
            self._connections.remove(connection)
        if self.running:
            current().timeout(2, self.fork_connection)
        if self._connecting == connection:
            self._connecting = None
            self.init_connection()
        logging.info("connection close %s", connection)

    def session(self, callback=None):
        if self._session is None:
            self.reopen(callback)
        elif callable(callback):
            callback(self, self._session)
        return self._session

    def on_session_suspend(self, session):
        self._session = None
        self.running = False

    def on_session_sleeping(self, session):
        self.running = False

    def on_session_wakeup(self, session):
        self.running = True
        self.init_connection()