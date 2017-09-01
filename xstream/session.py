# -*- coding: utf-8 -*-
#14-4-22
# create by: snower

import time
import random
import logging
import base64
import pickle
from sevent import EventEmitter, current, tcp
from crypto import Crypto, rand_string
from connection import Connection
from center import Center
from stream import Stream, StreamFrame

STATUS_INITED = 0x01
STATUS_OPENING = 0x02
STATUS_CLOSED = 0x03

ACTION_OPENING = 0x01
ACTION_KEYCHANGE = 0x02

class Session(EventEmitter):
    def __init__(self, session_id, auth_key, is_server=False, crypto=None, mss=None):
        super(Session, self).__init__()

        self._is_server = is_server
        self._session_id = session_id
        self._auth_key = auth_key
        self._crypto_ensecret = crypto._ensecret
        self._crypto_desecret = crypto._desecret
        self._crypto = crypto
        self._current_crypto_key =  '0' * 64
        self._mss = mss
        self._key_change = 1
        self._current_stream_id = 1 if is_server else 2
        self._connections = []
        self._streams = {}
        self._center = Center(self)
        self._data_time = time.time()
        self._status = STATUS_INITED
        self._controll_stream = self.create_stream(0, priority = 1, capped = True, expried_time = 0)
        self._controll_stream.on("data", self.on_controll_data)

        self._center.on("frame", self.on_frame)
        if not self._is_server:
            current().timeout(60, self.on_check_loop)

    @property
    def id(self):
        return self._session_id

    @property
    def auth_key(self):
        return self._auth_key

    @property
    def closed(self):
        return self._status == STATUS_CLOSED

    @property
    def key_change(self):
        return self._key_change < 1

    def dumps(self):
        return base64.b64encode(pickle.dumps({
            "session_id": self._session_id,
            "is_server": self._is_server,
            "auth_key": self._auth_key,
            "crypto_key": self._crypto._key,
            "crypto_alg": self._crypto._alg,
            "crypto_ensecret": list(self._crypto_ensecret),
            "crypto_desecret": list(self._crypto_desecret),
            "current_crypto_key": self._current_crypto_key,
            "key_change": self._key_change,
            "mss": self._mss,
            "t": time.time()
        }))

    @classmethod
    def loads(cls, s):
        try:
            s = pickle.loads(base64.b64decode(s))
            crypto = Crypto(s["crypto_key"], s["crypto_alg"])
            crypto._ensecret = tuple(s["crypto_ensecret"])
            crypto._desecret = tuple(s["crypto_desecret"])
            session = cls(s["session_id"], s["auth_key"], s["is_server"], crypto, s["mss"])
            session._current_crypto_key = s["current_crypto_key"]
            session._key_change = s["key_change"]
            if not s["is_server"] and session._key_change < 1:
                return None
        except:
            return None
        return session

    def get_encrypt_crypto(self, crypto_time):
        self._crypto.init_encrypt(crypto_time, self._crypto_ensecret, self._current_crypto_key)
        return self._crypto

    def get_decrypt_crypto(self, crypto_time):
        self._crypto.init_decrypt(crypto_time, self._crypto_desecret, self._current_crypto_key)
        return self._crypto

    def add_connection(self, conn):
        if self._status == STATUS_CLOSED:
            conn.close()
        else:
            for connection in self._connections:
                if conn.crypto_time == connection._connection.crypto_time:
                    return None

            connection = Connection(conn, self, self._mss)
            self._connections.append(connection)
            self._center.add_connection(connection)
            return connection
        return None

    def remove_connection(self, conn):
        for connection in self._connections:
            if connection._connection == conn:
                if self._center:
                    self._center.remove_connection(connection)
                self._connections.remove(connection)
                break

        if not self._connections:
            if self._status == STATUS_CLOSED:
                if self._center:
                    self._center.close()
                    self._center = None
                    self.emit("close", self)
                    self.remove_all_listeners()
            else:
                def on_exit():
                    if not self._connections:
                        self.do_close()

                if self._status == STATUS_OPENING:
                    current().timeout(15 * 60, on_exit)
                else:
                    current().async(on_exit)

    def on_frame(self, center, frame):
        self._data_time = time.time()
        if frame.action == 0:
            if not frame.data:
                return
            if self._status == STATUS_CLOSED:
                return

            stream_frame = StreamFrame.loads(frame.data)
            if stream_frame.stream_id not in self._streams:
                if stream_frame.action == 0x01:
                    priority, capped = 0, False
                    if stream_frame.flag & 0x02:
                        priority = 1
                    if stream_frame.flag & 0x04:
                        capped = True
                    self.create_stream(stream_frame.stream_id, priority = priority, capped = capped)
                elif stream_frame.action == 0x03:
                    data = rand_string(random.randint(1, 256))
                    frame = StreamFrame(stream_frame.stream_id, 0, 0x04, data)
                    self.write(frame)
            else:
                if stream_frame.action == 0x01:
                    return self._streams[stream_frame.stream_id].close()

            if stream_frame.stream_id in self._streams:
                self._streams[stream_frame.stream_id].on_frame(stream_frame)
        else:
            self.on_action(frame.action, frame.data)

    def on_controll_data(self, stream, buffer):
        data = buffer.next()
        while data:
            self.on_action(ord(data[0]), data[1:])
            data = buffer.next()

    def get_stream_id(self):
        stream_id = self._current_stream_id
        self._current_stream_id += 2
        if self._current_stream_id > 0xffff:
            self._current_stream_id = 1 if self._is_server else 2

        while stream_id in self._streams:
            stream_id = self._current_stream_id
            self._current_stream_id += 2
            if self._current_stream_id > 0xffff:
                self._current_stream_id = 1 if self._is_server else 2
        return stream_id

    def create_stream(self, stream_id = None, **kwargs):
        is_server = stream_id is not None
        if stream_id is None:
            stream_id = self.get_stream_id()
        stream = Stream(stream_id, self, is_server, self._mss, **kwargs)
        self._streams[stream_id] = stream
        self.emit("stream", self, stream)
        return stream

    def stream(self, callback=None, **kwargs):
        stream = self.create_stream(**kwargs)
        if callable(callback):
            callback(self, stream)
        if self._status == STATUS_CLOSED:
            current().async(stream.do_close)
        return stream

    def close_stream(self, stream):
        if stream.id in self._streams:
            self._streams.pop(stream.id)
        if self._status == STATUS_CLOSED:
            if not self._streams and self._center:
                self.do_close()

    def ready_write(self, stream, is_ready=True):
        if self._status == STATUS_CLOSED:
            if stream.id in self._streams:
                current().async(stream.do_close)
            return False
        return self._center.ready_write(stream, is_ready)

    def write(self, frame):
        if self._status == STATUS_CLOSED:
            if frame.stream_id in self._streams:
                current().async(self._streams[frame.stream_id].do_close)
            return False
        
        self._data_time = time.time()
        data = frame.dumps()
        return self._center.write(data)

    def on_action(self, action, data):
        if action & 0x80 == 0:
            return self._center.on_action(action, data)
        else:
            action = action & 0x7f

        if action == ACTION_OPENING:
            if self._status != STATUS_INITED:
                self.close()
                logging.info("xstream session %s opening error close", self)
            else:
                self._status = STATUS_OPENING
                logging.info("xstream session %s opening", self)
        elif action == ACTION_KEYCHANGE:
            status = ord(data[0])
            if status == 0:
                logging.info("xstream session %s error key change", self)
                return

            if self._is_server:
                if self._key_change != 0:
                    self.close()
                else:
                    self._current_crypto_key = data[1:65]
                    self._key_change += 1
                    self.emit("keychange", self)
                    logging.info("xstream session %s key change", self)
            else:
                if self._key_change == 1 or len(self._connections) < 2 or not self._center or self._center.ttl >= 800:
                    self.write_action(ACTION_KEYCHANGE, chr(0) + data[1:65], True)
                    logging.info("xstream session %s empty key change", self)
                else:
                    self._current_crypto_key = data[1:65]
                    self.write_action(ACTION_KEYCHANGE, chr(1) + self._current_crypto_key, True)
                    self._key_change = 1
                    self.emit("keychange", self)
                    logging.info("xstream session %s key change", self)

    def write_action(self, action, data='', index=None, center = False):
        if self._status == STATUS_CLOSED:
            return

        if not index:
            self._center.write_action(action | 0x80, data, 0)
        else:
            data += rand_string(random.randint(1, 256))
            action = chr(action) if center else chr(action | 0x80)
            self._controll_stream.write(action + data)

    def start_key_change(self):
        if self._key_change < 1:
            return

        if not self._center or self._center.ttl >= 800:
            return

        self._key_change -= 1
        if self._is_server:
            self.write_action(ACTION_KEYCHANGE, chr(1) + rand_string(64), True)
        else:
            def on_timeout():
                if self._key_change < 1:
                    self._key_change = 1
            current().timeout(10, on_timeout)

    def on_check_loop(self):
        if time.time() - self._data_time > 300 and not self._streams:
            self.do_close()
        else:
            current().timeout(60, self.on_check_loop)

    def close(self):
        if self._status == STATUS_CLOSED:
            return
        
        self._status = STATUS_CLOSED
        if not self._streams:
            return self.do_close()
            
        for stream_id, stream in self._streams.items():
            stream.do_close()

    def do_close(self):
        if self._center is None:
            return

        self._status = STATUS_CLOSED
        if self._connections:
            for connection in self._connections:
                if connection._connection and connection._connection._state == tcp.STATE_CLOSED:
                    current().async(self.remove_connection, connection._connection)
                else:
                    connection.close()
        else:
            self._center.close()
            self._center = None
            self.emit("close", self)
            self.remove_all_listeners()
        logging.info("xstream session %s close", self)

    def __del__(self):
        self.close()

    def __str__(self):
        return "<%s %s,%s,%s>" % (super(Session, self).__str__(), self._session_id, len(self._connections), len(self._streams))
