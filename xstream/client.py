# -*- coding: utf-8 -*-
# 14/12/10
# create by: snower

from ssloop import EventEmitter, Socket
from session import Session

class Client(EventEmitter):
    def __init__(self, host, port, max_connections=3):
        super(Client, self).__init__()

        self._host = host
        self._port = port
        self._max_connections = max_connections
        self._session = Session(1, False)

    def init_connection(self):
        for i in range(self._max_connections):
            connection = Socket()
            connection.connect((self._host, self._port))
            connection.on("connect", self.on_connect)

    def open(self):
        self.init_connection()

    def on_connect(self, connection):
        self._session.add_connection(connection)

    def session(self):
        return self._session