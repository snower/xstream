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
        if isinstance(self._host, (tuple, list)):
            self._server = [tcp.Server() for _ in range(len(self._host))]
        else:
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

                    if self.get_session_key(session["session_id"]) != filename:
                        os.remove(session_path + "/" + filename)
                        logging.info("xstream check session config change remove %s %s", session["session_id"], filename)

                    elif now - session["t"] > 7 * 24 * 60 * 60:
                        os.remove(session_path + "/" + filename)
                        logging.info("xstream check session expried remove %s %s", session["session_id"], filename)
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
        if isinstance(self._server, list):
            for i in range(len(self._server)):
                self._server[i].on("connection", self.on_connection)
                self._server[i].listen((self._host[i][0], self._host[i][1]))
        else:
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
        datas = str(data)
        action = datas[2]
        if action == '\x01':
            self.on_open_session(connection, data, datas)
        else:
            self.on_fork_connection(connection, data, datas)

    def on_open_session(self, connection, data, datas):
        data.read(11)
        crypto_time, = struct.unpack("!I", data.read(4))
        key = data.read(28)
        data.read(1)
        auth_key = data.read(16)
        key += data.read(16)
        data.read(2)
        auth = data.read(16)
        data.read(3)

        if crypto_time and key and auth_key and auth:
            crypto = Crypto(self._crypto_key, self._crypto_alg)
            crypto.init_decrypt(crypto_time, key)

            auth_key = crypto.decrypt(auth_key)
            if abs(crypto_time - time.time()) < 1800 and auth == sign_string(self._crypto_key + key + auth_key + str(crypto_time)):
                crypto_time = int(time.time())
                key = crypto.init_encrypt(crypto_time)
                session = self.create_session(connection, auth_key, crypto)

                session_id = xor_string(crypto_time & 0xff, struct.pack("!H", session.id))
                auth = crypto.encrypt(sign_string(self._crypto_key + key + auth_key + str(crypto_time)))

                data = "".join(['\x03\x03', struct.pack("!I", crypto_time), key[:28], '\x20', auth, key[28:], session_id, '\x00\x00'])
                connection.write("".join(['\x16\x03\x01', struct.pack("!H", len(data) + 4),
                                          '\x02\x00', struct.pack("!H", len(data)), data,
                                          '\x14\x03\x03\x00\x01\x01', '\x16\x03\x03\x00\x28', rand_string(40)]))

                session.on("close", self.on_session_close)
                session.on("keychange", self.save_session)
                self.emit("session", self, session)
                self.save_session(session)
                logging.info("xstream session open %s", session)
                return

        self.emit("connection", self, connection, datas)
        logging.info("xstream session open auth fail %s %s %s", connection, time.time(), crypto_time)

    def create_session(self, connection, auth_key, crypto):
        session = Session(self.get_session_id(), auth_key, True, crypto, StreamFrame.FRAME_LEN)
        self._sessions[session.id] = session
        self._used_session_ids[session.id] = self.get_session_key(session.id)
        return session

    def get_session_id(self):
        self._current_session_id = random.randint(0x0001, 0xffff)
        while self._current_session_id in self._used_session_ids:
            self._current_session_id = random.randint(0x0001, 0xffff)
        return self._current_session_id

    def on_fork_connection(self, connection, data, datas):
        try:
            data.read(11)
            crypto_time, = struct.unpack("!I", data.read(4))
            key = data.read(28)
            data.read(1)
            fork_auth_session_id = data.read(32)
            ciphres_len, = struct.unpack("!H", data.read(2))
            ciphres = data.read(ciphres_len)
            xsession_id = xor_string(crypto_time & 0xff, ciphres[:2], False)
            session_id, = struct.unpack("!H", xsession_id)
            data.read(2)
            extensions_len, = struct.unpack("!H", data.read(2))
            extensions = data.read(extensions_len)

            auth = extensions[4: 20]
            key += extensions[20: 36]

            if not (crypto_time, key, auth, session_id):
                self.emit("connection", self, connection, datas)
                logging.info("xstream connection refuse %s %s", connection, time.time())
                return
        except:
            self.emit("connection", self, connection, datas)
            logging.info("xstream connection refuse %s %s", connection, time.time())
            return

        if crypto_time and key and session_id and auth:
            is_loaded_session = False
            connection.is_connected_session = True
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
                    logging.info("xstream connection refuse session closed %s %s %s", session_id, connection, time.time())
                    self.emit("connection", self, connection, datas)
                    return

                if session.key_change:
                    logging.info("xstream connection key_change refuse session closed %s %s %s", session_id, connection, time.time())
                    self.emit("connection", self, connection, datas)
                    return

                crypto = session.get_decrypt_crypto(crypto_time)
                key = crypto.decrypt(key)

                if abs(crypto_time - time.time()) < 1800 and session.get_last_auth_time() < crypto_time \
                        and auth == sign_string(self._crypto_key + key + session.auth_key + str(crypto_time)):
                    session.set_last_auth_time(crypto_time)
                    setattr(connection, "crypto", Crypto(self._crypto_key, self._crypto_alg))
                    setattr(connection, "crypto_time", crypto_time)
                    connection.crypto.init_decrypt(crypto_time, key)

                    crypto_time = int(time.time())
                    key = connection.crypto.init_encrypt(crypto_time)
                    auth = sign_string(self._crypto_key + key + session.auth_key + str(crypto_time))

                    crypto = session.get_encrypt_crypto(crypto_time)
                    key = crypto.encrypt(key)

                    data = "".join(['\x00\x05\x00\x00', '\x00\x10\x00\x05\x00\x03\x02\x68\x32'])

                    data = "".join(
                        ['\x03\x03', struct.pack("!I", crypto_time), key[:28], '\x20', fork_auth_session_id,
                         xsession_id, '\x00', struct.pack("!H", len(data)), data])

                    connection.write("".join(['\x16\x03\x03', struct.pack("!H", len(data) + 4),
                                              '\x02\x00', struct.pack("!H", len(data)), data,
                                              '\x14\x03\x03\x00\x01\x01', '\x16\x03\x03\x00\x28', auth, key[28:], rand_string(8)]))

                    def add_connection(conn):
                        connection = session.add_connection(conn)
                        if connection:
                            if is_loaded_session:
                                def do_write_action():
                                    session.write_action(0x01)
                                current().async(do_write_action)

                            if len(session._connections) >= 2:
                                def on_timeout_start_key_change():
                                    if len(session._connections) >= 2:
                                        session.start_key_change()
                                current().timeout(2, on_timeout_start_key_change)
                        else:
                            self.emit("connection", self, conn, datas)

                    current().async(add_connection, connection)

                    def on_fork_connection_close(connection):
                        session.remove_connection(connection)
                        logging.info("xstream connection close %s %s", session, connection)
                    connection.on("close", on_fork_connection_close)
                    logging.info("xstream connection connect %s %s", session, connection)
                    return
        self.emit("connection", self, connection, datas)
        logging.info("xstream connection refuse %s %s %s", session_id, connection, time.time())

    def on_session_close(self, session):
        if session.id in self._sessions:
            self.save_session(session)
            self._sessions.pop(session.id)
            logging.info("xstream session close %s", session)
