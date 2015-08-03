# -*- coding: utf-8 -*-
# 14/12/10
# create by: snower

import logging
import struct
import socket
from sevent import EventEmitter, tcp, current
from session import Session
from crypto import Crypto

class Server(EventEmitter):
    def __init__(self, port, host='0.0.0.0', crypto_key='', crypto_alg=''):
        super(Server, self).__init__()

        self._host = host
        self._port = port
        self._server = tcp.Server()
        self._sessions = {}
        self._current_session_id = 1
        self._crypto_key = crypto_key
        self._crypto_alg = crypto_alg

    def start(self):
        self._server.on("connection", self.on_connection)
        self._server.listen((self._host, self._port))

    def on_connection(self, server, connection):
        connection.once("data", self.on_data)

    def on_data(self, connection, data):
        action = ord(data.read(1))
        if action == 0:
            self.on_open_session(connection, data)
        else:
            self.on_fork_connection(connection, data)

    def on_open_session(self, connection, data):
        auth_key = data.read(16)
        crypto = Crypto(self._crypto_key, self._crypto_alg)
        crypto.init_decrypt(data.read(64))
        key = crypto.init_encrypt()
        session = self.create_session(connection, auth_key, crypto)
        connection.write(struct.pack("!H", session.id) + key)
        session.on("close", self.on_session_close)
        self.emit("session", self, session)
        logging.info("xstream session open %s", session)

    def create_session(self, connection, auth_key, crypto):
        mss = (connection._socket.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG) or 1460) * 4 - 32
        session = Session(self.get_session_id(), auth_key, True, crypto, mss)
        self._sessions[session.id] = session
        return session

    def get_session_id(self):
        while self._current_session_id in self._sessions:
            self._current_session_id += 1
        session_id = self._current_session_id
        self._current_session_id += 1
        return session_id

    def on_fork_connection(self, connection, data):
        session_id, = struct.unpack("!H", data.read(2))
        if session_id in self._sessions:
            session = self._sessions[session_id]
            data = session._crypto.decrypt(data.read(80))
            auth_key = data[:16]
            if auth_key == session.auth_key:
                key = data[16:]
                setattr(connection, "crypto", Crypto(self._crypto_key, self._crypto_alg))
                connection.crypto.init_decrypt(key)
                key = connection.crypto.init_encrypt()
                def add_connection():
                    session.add_connection(connection)
                current().sync(add_connection)
                data = session._crypto.encrypt(key)
                connection.write(data)

                def on_fork_connection_close(connection):
                    session.remove_connection(connection)
                    logging.info("xstream connection close %s %s", session, connection)
                connection.on("close", on_fork_connection_close)
                logging.info("xstream connection connect %s %s", session, connection)
                return
        connection.close()
        logging.info("xstream connection refuse %s %s", session_id, connection)

    def on_session_close(self, session):
        session = self._sessions.pop(session.id)
        logging.info("xstream session close %s", session)
