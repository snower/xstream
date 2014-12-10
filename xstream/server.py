# -*- coding: utf-8 -*-
# 14/12/10
# create by: snower

from ssloop import EventEmitter, Server as LoopServer
from session import Session

class Server(EventEmitter):
    def __init__(self, port, host='0.0.0.0'):
        super(Server, self).__init__()

        self._host = host
        self._port = port
        self._server = LoopServer((self._host, self._port))
        self._session = None

    def start(self):
        self._server.on("connection", self.on_connection)
        self._server.listen()

    def on_connection(self, server, connection):
        if self._session is None:
            self._session = Session(1, True)
            self.emit("session", self, self._session)
        self._session.add_connection(connection)

    def session(self):
        return self._session