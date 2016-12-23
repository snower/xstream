# -*- coding: utf-8 -*-
#14-4-22
# create by: snower

import time
import logging
from sevent import EventEmitter, current
from connection import Connection
from center import Center
from stream import Stream, StreamFrame
from crypto import rand_string

STATUS_INITED = 0x01
STATUS_OPENING = 0x02
STATUS_CLOSED = 0x03

class Session(EventEmitter):
    def __init__(self, session_id, auth_key, is_server=False, crypto=None, mss=None):
        super(Session, self).__init__()

        self._is_server = is_server
        self._session_id = session_id
        self._auth_key = auth_key
        self._crypto_ensecret = crypto._ensecret
        self._crypto_desecret = crypto._desecret
        self._crypto = crypto
        self._crypto_keys = {}
        self._current_crypto_key = {}
        self._mss = mss
        self._current_stream_id = 1 if is_server else 2
        self._connections = []
        self._streams = {}
        self._center = Center(self)
        self._data_time = time.time()
        self._status = STATUS_INITED

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
    def current_crypto_key(self):
        if not self._current_crypto_key:
            return (0, '0' * 64)
        return self._current_crypto_key

    @current_crypto_key.setter
    def current_crypto_key(self, value):
        self._current_crypto_key = value
        self._crypto_keys[value[0]] = value[1]

        if len(self._crypto_keys) >= 5:
            now = time.time()
            for key_time in self._crypto_keys.keys():
                if now - key_time > 2 * 60 * 60:
                    del self._crypto_keys[key_time]

    def get_crypto_key(self, crypto_time):
        if crypto_time not in self._crypto_keys:
            return None
        return self._crypto_keys[crypto_time]

    def get_encrypt_crypto(self, crypto_time):
        current_crypto_key = self.current_crypto_key
        if not current_crypto_key:
            current_crypto_key = (0, '0' * 64)

        self._crypto.init_encrypt(crypto_time, self._crypto_ensecret, current_crypto_key[1])
        return self._crypto

    def get_decrypt_crypto(self, crypto_time, last_crypto_time):
        current_crypto_key = self.get_crypto_key(last_crypto_time)
        if not current_crypto_key:
            current_crypto_key = '0' * 64

        self._crypto.init_decrypt(crypto_time, self._crypto_desecret, current_crypto_key)
        return self._crypto

    def add_connection(self, conn):
        if self._status == STATUS_CLOSED:
            conn.close()
        else:
            connection = Connection(conn, self)
            self._connections.append(connection)
            self._center.add_connection(connection)

    def remove_connection(self, conn):
        for connection in self._connections:
            if connection._connection == conn:
                self._center.remove_connection(connection)
                self._connections.remove(connection)
                break

        if not self._connections:
            if self._status == STATUS_CLOSED:
                self._center.close()
                self._center = None
                self.emit("close", self)
                self.remove_all_listeners()
            else:
                def on_exit():
                    if not self._connections:
                        self.do_close()
                current().timeout(300, on_exit)

    def on_frame(self, center, frame):
        self._data_time = time.time()
        if frame.action == 0:
            if not frame.data:
                return
            stream_frame = StreamFrame.loads(frame.data)
            if stream_frame.action == 0x01:
                priority, capped = 0, False
                if stream_frame.flag & 0x02:
                    priority = 1
                if stream_frame.flag & 0x04:
                    capped = True
                self.create_stream(stream_frame.stream_id, priority = priority, capped = capped)
            if stream_frame.stream_id in self._streams:
                self._streams[stream_frame.stream_id].on_frame(stream_frame)
        else:
            self.on_action(frame.action, frame.data)

    def get_stream_id(self):
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
        if self._status == STATUS_CLOSED and not self._streams:
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
        if action & 0x8000 == 0:
            self._center.on_action(action, data)

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
            if self._connections:
                stream.close()
            else:
                stream.do_close()

    def do_close(self):
        if self._center is None:
            return

        self._status = STATUS_CLOSED
        if self._connections:
            for connection in self._connections:
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
        return "<%s %s>" % (super(Session, self).__str__(), self._session_id)
