# -*- coding: utf-8 -*-
# 14/12/10
# create by: snower

import os
import time
import logging
import struct
import random
import hashlib
import pickle
import base64
from sevent import EventEmitter, tcp, current
from .session import Session
from .crypto import Crypto, rand_string, xor_string, sign_string, CIPHER_SUITES
from .frame import StreamFrame

class Server(EventEmitter):
    def __init__(self, port, host='0.0.0.0', crypto_key='', crypto_alg=''):
        super(Server, self).__init__()

        self._host = host
        self._port = port
        if isinstance(self._host, (tuple, list)):
            self._server = []
            for _ in range(len(self._host)):
                server = tcp.Server()
                server.enable_nodelay()
                server.enable_reuseaddr()
                self._server.append(server)
        else:
            self._server = tcp.Server()
            self._server.enable_nodelay()
            self._server.enable_reuseaddr()

        self._used_session_ids = {}
        self._sessions = {}
        self._current_session_id = 1
        self._crypto_key = crypto_key
        self._crypto_alg = crypto_alg
        self._fork_auth_fail_count = 0

        current().add_timeout(120, self.on_check_session_timeout)

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
                with open(session_path + "/" + filename, encoding="utf-8") as fp:
                    session = pickle.loads(base64.b64decode(fp.read()))
                    if not session["is_server"]:
                        continue

                    if self.get_session_key(session["session_id"]) != filename:
                        os.remove(session_path + "/" + filename)
                        logging.info("xstream check session config change remove %s %s", session["session_id"], filename)

                    elif now - session["timestamp"] > 7 * 24 * 60 * 60:
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
                with open(session_path + "/" + session_key, encoding="utf-8") as fp:
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
        with open(session_path + "/" + session_key, "w", encoding="utf-8") as fp:
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
        current().add_timeout(6 * 60 * 60, self.check_session)

    def on_connection(self, server, connection):
        connection.once("data", self.on_data)
        setattr(connection, "is_connected_session", False)
        setattr(connection, "is_connected_dataed", False)
        def on_timeout():
            if not connection.is_connected_dataed:
                connection.close()
        current().add_timeout(random.randint(1200, 3000) / 1000.0, on_timeout)

    def on_data(self, connection, data):
        connection.is_connected_dataed = True
        datas = b"".join([b'', data.join()])
        action = datas[2]
        if action == 1:
            self.on_open_session(connection, data, datas)
        else:
            self.on_fork_connection(connection, data, datas)

    def on_open_session(self, connection, data, datas):
        data.read(9)
        session_id = data.read(2)
        if session_id == b'\x03\x03':
            session_id = 0
        else:
            session_id, = struct.unpack("!H", session_id)
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
            if abs(crypto_time - time.time()) < 1800 and auth == sign_string(self._crypto_key.encode("utf-8") + key + auth_key + str(crypto_time).encode("utf-8")):
                crypto_time = int(time.time())
                key = crypto.init_encrypt(crypto_time)
                session = self.create_session(connection, auth_key, crypto, session_id)
                self._sessions[session.id] = session

                session_id = xor_string(crypto_time & 0xff, struct.pack("!H", session.id))
                auth = crypto.encrypt(sign_string(self._crypto_key.encode("utf-8") + key + auth_key + str(crypto_time).encode("utf-8")))

                data = b"".join([b'\x03\x03', struct.pack("!I", crypto_time), key[:28], b'\x20', auth, key[28:], session_id, b'\x00\x00'])
                connection.write(b"".join([b'\x16\x03\x01', struct.pack("!H", len(data) + 4),
                                          b'\x02\x00', struct.pack("!H", len(data)), data,
                                          b'\x14\x03\x03\x00\x01\x01', b'\x16\x03\x03\x00\x28', rand_string(40)]))

                session.on("close", self.on_session_close)
                session.on("keyexchange", self.save_session)
                self.emit_session(self, session)
                self.save_session(session)
                logging.info("xstream session open %s", session)
                return

        def on_fork_fail_connection_close(connection):
            self._fork_auth_fail_count -= 1

        connection.on("close", on_fork_fail_connection_close)
        self._fork_auth_fail_count += 1
        if self._fork_auth_fail_count >= 128:
            connection.close()
        else:
            self.emit_connection(self, connection, datas)
        logging.info("xstream session open auth fail %s %s %s", connection, time.time(), crypto_time)

    def create_session(self, connection, auth_key, crypto, session_id=0):
        if session_id:
            if session_id in self._sessions:
                if self._sessions[session_id]._connections:
                    session_id = self.get_session_id()
                else:
                    self._sessions[session_id].close()
                    self._sessions.pop(session_id)
        else:
            session_id = self.get_session_id()
        session = Session(session_id, auth_key, True, crypto, StreamFrame.FRAME_LEN)
        self._used_session_ids[session.id] = self.get_session_key(session.id)
        return session

    def get_session_id(self):
        for cs in CIPHER_SUITES:
            if cs in self._used_session_ids:
                continue
            self._current_session_id = cs
            return cs

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
            session_id, = struct.unpack("!H", ciphres[:2])
            data.read(2)
            extensions_len, = struct.unpack("!H", data.read(2))
            extensions = data.read(extensions_len)

            auth = extensions[4: 20]
            key += extensions[20: 36]

            if not (crypto_time, key, auth, session_id):
                self.emit_connection(self, connection, datas)
                logging.info("xstream connection refuse %s %s", connection, time.time())
                return
        except:
            self.emit_connection(self, connection, datas)
            logging.info("xstream connection refuse %s %s", connection, time.time())
            return

        if crypto_time and key and session_id and auth:
            is_loaded_session = False
            if session_id not in self._sessions:
                session = self.load_session(session_id)
                if session:
                    self._sessions[session.id] = session
                    session.on("close", self.on_session_close)
                    session.on("keyexchange", self.save_session)
                    self.emit_session(self, session)
                    is_loaded_session = True
                    logging.info("xstream session open %s", session)

            if session_id in self._sessions:
                session = self._sessions[session_id]
                if session.closed:
                    logging.info("xstream connection refuse session closed %s %s %s", session_id, connection, time.time())
                    self.emit_connection(self, connection, datas)
                    return

                crypto = session.get_decrypt_crypto(crypto_time)
                key = crypto.decrypt(key)

                if abs(crypto_time - time.time()) < 1800 and session.get_last_auth_time() < crypto_time \
                        and auth == sign_string(self._crypto_key.encode("utf-8") + key + session.auth_key + str(crypto_time).encode("utf-8")):
                    if key in session._auth_cache:
                        logging.info("xstream connection auth reuse session closed %s %s %s", session_id, connection, time.time())
                        connection.close()
                        return
                    session._auth_cache[key] = time.time()

                    session.set_last_auth_time(crypto_time)
                    setattr(connection, "crypto", Crypto(self._crypto_key, self._crypto_alg))
                    setattr(connection, "crypto_time", crypto_time)
                    connection.crypto.init_decrypt(crypto_time, key)

                    crypto_time = int(time.time())
                    key = connection.crypto.init_encrypt(crypto_time)
                    auth = sign_string(self._crypto_key.encode("utf-8") + key + session.auth_key + str(crypto_time).encode("utf-8"))

                    crypto = session.get_encrypt_crypto(crypto_time)
                    key = crypto.encrypt(key)

                    data = b"".join([b'\xff\x01\x00\x01\x00', b'\x00\x17\x00\x00', b'\x00\x10\x00\x05\x00\x03\x02\x68\x32'])

                    data = b"".join(
                        [b'\x03\x03', struct.pack("!I", crypto_time), key[:28], b'\x20', fork_auth_session_id,
                         struct.pack("!H", session_id), b'\x00', struct.pack("!H", len(data)), data])

                    connection.write(b"".join([b'\x16\x03\x03', struct.pack("!H", len(data) + 4),
                                              b'\x02\x00', struct.pack("!H", len(data)), data,
                                              b'\x14\x03\x03\x00\x01\x01', b'\x16\x03\x03\x00\x28', auth, key[28:], rand_string(8)]))

                    if not is_loaded_session and session._status == 0x01:
                        is_loaded_session = True

                    def add_connection(conn):
                        connection = session.add_connection(conn)
                        if connection:
                            if is_loaded_session:
                                def do_write_action():
                                    session.write_action(0x01)
                                current().add_async(do_write_action)

                            if time.time() - session.key_exchanged_time > 7200:
                                def on_timeout_start_key_exchange():
                                    if time.time() - session.key_exchanged_time > 7200:
                                        session.start_key_exchange()
                                current().add_timeout(random.randint(0, 3), on_timeout_start_key_exchange)

                            connection._expried_seconds_timer = current().add_timeout(7200, connection.on_expried)
                        else:
                            conn.close()
                    current().add_async(add_connection, connection)

                    connection.is_connected_session = True
                    self._fork_auth_fail_count = 0
                    def on_fork_connection_close(connection):
                        session.remove_connection(connection)
                        logging.info("xstream connection close %s %s", session, connection)
                    connection.on("close", on_fork_connection_close)
                    logging.info("xstream connection connect %s %s", session, connection)
                    return

                if not session.key_exchanged:
                    logging.info("xstream connection key exchanged refuse session closed %s %s %s", session_id, connection, time.time())
                    self.emit_connection(self, connection, datas)
                    return

        def on_fork_fail_connection_close(connection):
            self._fork_auth_fail_count -= 1

        connection.on("close", on_fork_fail_connection_close)
        self._fork_auth_fail_count += 1
        if self._fork_auth_fail_count >= 128:
            connection.close()
        else:
            self.emit_connection(self, connection, datas)
        logging.info("xstream connection refuse %s %s %s", session_id, connection, time.time())

    def on_check_session_timeout(self):
        try:
            now = time.time()
            for session_id, session in tuple(self._sessions.items()):
                if session._data_time and now - session._data_time >= 15 * 60:
                    try:
                        session.close()
                    except Exception as e:
                        logging.info("xstream session timeout close error %s %s", session, e)
                    else:
                        logging.info("xstream session timeout close %s", session)
        finally:
            current().add_timeout(120, self.on_check_session_timeout)

    def on_session_close(self, session):
        if session.id in self._sessions and self._sessions[session.id] == session:
            self.save_session(session)
            self._sessions.pop(session.id)
            logging.info("xstream session close %s", session)
