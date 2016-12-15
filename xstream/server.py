# -*- coding: utf-8 -*-
# 14/12/10
# create by: snower

import time
import logging
import struct
import socket
import random
from sevent import EventEmitter, tcp, current
from session import Session
from crypto import Crypto, rand_string, xor_string, get_crypto_time, sign_string, pack_protocel_code, unpack_protocel_code
from frame import StreamFrame

class Server(EventEmitter):
    def __init__(self, port, host='0.0.0.0', crypto_key='', crypto_alg=''):
        super(Server, self).__init__()

        self._host = host
        self._port = port
        self._server = tcp.Server()
        self._sessions = {}
        self._current_session_id = 1
        self._crypto_key = crypto_key.encode("utf-8") if isinstance(crypto_key, unicode) else crypto_key
        self._crypto_alg = crypto_alg

    def start(self):
        self._server.on("connection", self.on_connection)
        self._server.listen((self._host, self._port))

    def on_connection(self, server, connection):
        connection.once("data", self.on_data)

    def on_data(self, connection, data):
        rand_code, action, crypto_time = unpack_protocel_code(data.read(2))
        if action == 0:
            self.on_open_session(connection, data, crypto_time)
        else:
            self.on_fork_connection(connection, data, rand_code, crypto_time)

    def on_open_session(self, connection, data, crypto_time):
        if len(data) >= 96:
            key = data.read(64)
            crypto = Crypto(self._crypto_key, self._crypto_alg)
            crypto.init_decrypt(crypto_time, key)

            auth = crypto.decrypt(data.read(32))
            auth_key = auth[:16]
            if auth[16:] == sign_string(self._crypto_key + key + auth_key + str(crypto_time)):
                crypto_time = get_crypto_time()
                key = crypto.init_encrypt(crypto_time)
                session = self.create_session(connection, auth_key, crypto)

                rand_code, protocel_code = pack_protocel_code(crypto_time, 0)
                session_id = xor_string(rand_code & 0xff, struct.pack("!H", session.id))
                auth = crypto.encrypt(sign_string(self._crypto_key + key + auth_key + str(crypto_time)))
                connection.write(protocel_code + session_id + key + auth + rand_string(random.randint(1024, 4096)))

                session.on("close", self.on_session_close)
                self.emit("session", self, session)
                logging.info("xstream session open %s", session)
                return
        connection.close()
        logging.info("xstream session open auth fail %s %s %s", connection, time.time(), crypto_time)

    def create_session(self, connection, auth_key, crypto):
        mss = min((connection._socket.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG) or 1460) * 2 - 32, StreamFrame.FRAME_LEN)
        session = Session(self.get_session_id(), auth_key, True, crypto, mss)
        self._sessions[session.id] = session
        return session

    def get_session_id(self):
        while self._current_session_id in self._sessions:
            self._current_session_id += 1
        session_id = self._current_session_id
        self._current_session_id += 1
        return session_id

    def on_fork_connection(self, connection, data, rand_code, crypto_time):
        session_id = ''
        if len(data) >= 84:
            session_id, = struct.unpack("!H", xor_string(rand_code & 0xff, data.read(2), False))
            if session_id in self._sessions:
                session = self._sessions[session_id]
                decrypt_data = session._crypto.decrypt(data.read(82))
                auth = decrypt_data[:16]
                key = decrypt_data[16:80]

                if auth == sign_string(self._crypto_key + key + session.auth_key + str(crypto_time)):
                    setattr(connection, "crypto", Crypto(self._crypto_key, self._crypto_alg))
                    connection.crypto.init_decrypt(crypto_time, key)
                    obstruction_len, = struct.unpack("!H", decrypt_data[80:82])
                    data.read(obstruction_len)

                    crypto_time = get_crypto_time()
                    key = connection.crypto.init_encrypt(crypto_time)
                    rand_code, protocel_code = pack_protocel_code(crypto_time, 0)
                    auth = sign_string(self._crypto_key + key + session.auth_key + str(crypto_time))
                    obstruction_len = random.randint(1, 1200)
                    obstruction = rand_string(obstruction_len)

                    data = session._crypto.encrypt(auth + key + struct.pack("!H", obstruction_len))
                    connection.write(protocel_code + data + obstruction)

                    def add_connection():
                        session.add_connection(connection)
                    current().async(add_connection)

                    def on_fork_connection_close(connection):
                        session.remove_connection(connection)
                        logging.info("xstream connection close %s %s", session, connection)
                    connection.on("close", on_fork_connection_close)
                    logging.info("xstream connection connect %s %s", session, connection)
                    return
        connection.close()
        logging.info("xstream connection refuse %s %s %s %s", session_id, connection, time.time(), crypto_time)

    def on_session_close(self, session):
        session = self._sessions.pop(session.id)
        logging.info("xstream session close %s", session)
