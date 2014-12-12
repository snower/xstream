# -*- coding: utf-8 -*-
# 14/12/10
# create by: snower

import logging
import struct
from ssloop import EventEmitter, Socket, current
from session import Session

class Client(EventEmitter):
    def __init__(self, host, port, max_connections=3):
        super(Client, self).__init__()

        self._host = host
        self._port = port
        self._max_connections = max_connections
        self._connections = []
        self._session = None

    def init_connection(self):
        for i in range(self._max_connections):
            self.fork_connection()

    def open(self):
        connection = Socket()
        connection.connect((self._host, self._port))
        connection.on("connect", self.on_connect)

    def close(self):
        for connection in self._connections:
            connection.close()

    def on_connect(self, connection):
        connection.write('\x00')
        connection.on("data", self.on_data)

    def on_data(self, connection, data):
        session_id, = struct.unpack("!H", data)
        self._session = Session(session_id)
        connection.close()
        self.emit("session", self, self._session)
        self.init_connection()

    def fork_connection(self):
        connection = Socket()
        connection.connect((self._host, self._port))
        connection.on("connect", self.on_fork_connect)
        self._connections.append(connection)

    def on_fork_connect(self, connection):
        connection.write(struct.pack("!BH", 1, self._session.id))
        self._session.add_connection(connection)
        connection.on("close", self.on_fork_close)
        logging.info("connection connect %s", connection)

    def on_fork_close(self, connection):
        self._session.remove_connection(connection)
        if connection in self._connections:
            self._connections.remove(connection)
        current().timeout(2, self.fork_connection)
        logging.info("connection close %s", connection)

    def session(self):
        return self._session