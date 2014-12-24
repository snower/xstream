# -*- coding: utf-8 -*-
# 14/12/10
# create by: snower

import logging
import struct
from ssloop import EventEmitter, Server as LoopServer, current
from session import Session
from crypto import Crypto

class Server(EventEmitter):
    def __init__(self, port, host='0.0.0.0', crypto_key='', crypto_alg=''):
        super(Server, self).__init__()

        self._host = host
        self._port = port
        self._server = LoopServer((self._host, self._port))
        self._sessions = {}
        self._current_session_id = 1
        self.crypto_key = crypto_key
        self.crypto_alg = crypto_alg
        self.crypto = Crypto(self.crypto_key, self.crypto_alg)

    def start(self):
        self._server.on("connection", self.on_connection)
        self._server.listen()

    def on_connection(self, server, connection):
        connection.once("data", self.on_data)

    def on_data(self, connection, data):
        action = ord(data[0])
        if action == 0:
            self.on_open_session(connection, data[1:])
        else:
            self.on_fork_connection(connection, data[1:])

    def on_open_session(self, connection, data):
        self.crypto.init_decrypt(data)
        key = self.crypto.init_encrypt()
        session = self.create_session()
        connection.write(struct.pack("!H", session.id) + key)
        session.on("suspend", self.on_session_suspend)
        self.emit("session", self, session)
        logging.info("session open %s", session)

    def create_session(self):
        session = Session(self.get_session_id(), True)
        self._sessions[session.id] = session
        return session

    def get_session_id(self):
        while self._current_session_id in self._sessions:
            self._current_session_id += 1
        session_id = self._current_session_id
        self._current_session_id += 1
        return session_id

    def on_fork_connection(self, connection, data):
        data = self.crypto.decrypt(data)
        session_id, = struct.unpack("!H", data[:2])
        if session_id in self._sessions:
            key = data[2:]
            setattr(connection, "crypto", Crypto(self.crypto_key, self.crypto_alg))
            connection.crypto.init_decrypt(key)
            key = connection.crypto.init_encrypt()
            session = self._sessions[session_id]
            session.add_connection(connection)
            connection.write(key)

            def on_fork_connection_close(connection):
                session.remove_connection(connection)
                logging.info("connection close %s %s", session, connection)
            connection.on("close", on_fork_connection_close)
            logging.info("connection connect %s %s", session, connection)
        else:
            connection.close()
            logging.info("connection refuse %s %s", session_id, connection)

    def on_session_suspend(self, session):
        current().timeout(30, self.on_session_close, session)

    def on_session_close(self, session):
        if not session._connections:
            self._sessions.pop(session.id)
            logging.info("session close %s", session)