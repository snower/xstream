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
import pickle
import base64
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
        self._used_session_ids = {}
        self._sessions = {}
        self._current_session_id = 1
        self._crypto_key = crypto_key.encode("utf-8") if isinstance(crypto_key, unicode) else crypto_key
        self._crypto_alg = crypto_alg

    def get_session_key(self, session_id):
        return hashlib.md5("".join([str(self._host), str(self._port), self._crypto_key, self._crypto_alg, str(session_id)]).encode("utf-8")).hexdigest()

    def get_session_path(self):
        session_path = os.environ.get("SESSION_PATH")
        if session_path:
            return os.path.abspath(session_path)
        return os.path.abspath("./session")

    def check_session(self):
        self._used_session_ids = {}

        for session_id in self._sessions:
            self._used_session_ids[session_id] = self.get_session_key(session_id)

        session_path = self.get_session_path()
        if not os.path.exists(session_path + "/"):
            os.makedirs(session_path + "/")

        now = time.time()
        for filename in os.listdir(session_path + "/"):
            try:
                with open(session_path + "/" + filename) as fp:
                    session = pickle.loads(base64.b64decode(fp.read()))
                    if not session["is_server"]:
                        continue

                    if now - session["t"] > 7 * 24 * 60 * 60:
                        os.remove(session_path + "/" + filename)
                        logging.info("xstream check session remove %s %s", session["session_id"], filename)
                    else:
                        self._used_session_ids[session["session_id"]] = filename
                        logging.info("xstream check session %s %s", session["session_id"], filename)
            except Exception as e:
                logging.info("xstream check session error %s %s", filename, e)

    def load_session(self, session_id):
        session_path = self.get_session_path()
        try:
            if not os.path.exists(session_path + "/"):
                os.makedirs(session_path + "/")
            session_key = self.get_session_key(session_id)
            if os.path.exists(session_path + "/" + session_key):
                with open(session_path + "/" + session_key) as fp:
                    session = Session.loads(fp.read())
                    if session:
                        logging.info("xstream load session %s %s", self, session)
                        return session
        except Exception as e:
            logging.error("xstream load session fail %s", self)
        return None

    def save_session(self, session):
        session_path = self.get_session_path()
        if not os.path.exists(session_path + "/"):
            os.makedirs(session_path + "/")
        session_key = self.get_session_key(session.id)
        session = session.dumps()
        with open(session_path + "/" + session_key, "w") as fp:
            fp.write(session)

    def start(self):
        self.check_session()
        self._server.on("connection", self.on_connection)
        self._server.listen((self._host, self._port))
        current().timeout(6 * 60 * 60, self.check_session)

    def on_connection(self, server, connection):
        connection.once("data", self.on_data)
        setattr(connection, "is_connected_session", False)
        def on_timeout():
            if not connection.is_connected_session:
                connection.close()
        current().timeout(random.randint(5, 30), on_timeout)

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
                connection.write(protocel_code + session_id + key + auth + rand_string(random.randint(512, 4096)))

                session.on("close", self.on_session_close)
                session.on("keychange", self.save_session)
                self.emit("session", self, session)
                self.save_session(session)
                logging.info("xstream session open %s", session)
                return
        connection.close()
        logging.info("xstream session open auth fail %s %s %s", connection, time.time(), crypto_time)

    def create_session(self, connection, auth_key, crypto):
        mss = min((connection._socket.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG) or 1460) * 2 - 32, StreamFrame.FRAME_LEN)
        session = Session(self.get_session_id(), auth_key, True, crypto, mss)
        self._sessions[session.id] = session
        self._used_session_ids[session.id] = self.get_session_key(session.id)
        return session

    def get_session_id(self):
        while self._current_session_id in self._used_session_ids:
            self._current_session_id += 1
        session_id = self._current_session_id
        self._current_session_id += 1
        return session_id

    def on_fork_connection(self, connection, data, rand_code, crypto_time):
        session_id = ''
        if len(data) >= 148:
            is_loaded_session = False
            connection.is_connected_session = True
            session_id, = struct.unpack("!H", xor_string(rand_code & 0xff, data.read(2), False))
            if session_id not in self._sessions:
                session = self.load_session(session_id)
                if session:
                    self._sessions[session.id] = session
                    session.on("close", self.on_session_close)
                    session.on("keychange", self.save_session)
                    self.emit("session", self, session)
                    is_loaded_session = True
                    logging.info("xstream session open %s", session)

            if session_id in self._sessions:
                session = self._sessions[session_id]
                if session.closed:
                    logging.info("xstream connection refuse session closed %s %s %s %s", session_id, connection, time.time())
                    return

                crypto = session.get_decrypt_crypto(crypto_time)
                decrypt_data = crypto.decrypt(data.read(82))
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
                    obstruction_len = random.randint(128, 1024)
                    obstruction = rand_string(obstruction_len)

                    crypto = session.get_encrypt_crypto(crypto_time)
                    data = crypto.encrypt(auth + key + struct.pack("!H", obstruction_len))

                    connection.write(protocel_code + data + obstruction)

                    def add_connection(conn):
                        connection = session.add_connection(conn)
                        if connection:
                            connection.write_action(0x05, rand_string(random.randint(2 * 1024, 32 * 1024)))
                            if is_loaded_session:
                                session.write_action(0x01)
                    current().async(add_connection, connection)

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
