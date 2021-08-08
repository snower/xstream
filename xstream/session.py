# -*- coding: utf-8 -*-
#14-4-22
# create by: snower

import time
import random
import logging
import base64
import struct
import pickle
import socket
from sevent import EventEmitter, current, tcp
from .crypto import Crypto, rand_string
from .connection import Connection
from .center import Center
from .stream import Stream
from .frame import StreamFrame
from .utils import format_data_len

STATUS_INITED = 0x01
STATUS_OPENING = 0x02
STATUS_CLOSED = 0x03

ACTION_OPENING = 0x01
ACTION_KEYEXCHANGE = 0x02

class Session(EventEmitter):
    def __init__(self, session_id, auth_key, is_server=False, crypto=None, mss=None):
        super(Session, self).__init__()

        self._is_server = is_server
        self._session_id = session_id
        self._auth_key = auth_key
        self._auth_cache = {}
        self._crypto_ensecret = crypto._ensecret
        self._crypto_desecret = crypto._desecret
        self._crypto = crypto
        self._current_crypto_key = b'0' * 64
        self._last_auth_time = 0
        self._mss = mss
        self._key_exchanged = True
        self._key_exchanged_count = 1
        self._key_exchanged_time = 0
        self._current_stream_id = 1 if is_server else 2
        self._connections = []
        self._streams = {}
        self._center = Center(self)
        self._data_time = time.time()
        self._status = STATUS_INITED
        self._controll_stream = self.create_stream(0, priority=1, capped=True, expried_time=0)
        self._controll_stream.on("data", self.on_controll_data)
        self._center.on("frame", self.on_frame)

        self._rdata_len = 0
        self._wdata_len = 0
        self._rpdata_count = 0
        self._wpdata_count = 0
        self._rfdata_count = 0
        self._wfdata_count = 0

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
    def key_exchanged(self):
        return self._key_exchanged

    @property
    def key_exchanged_time(self):
        return self._key_exchanged_time

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
            "last_auth_time": self._last_auth_time,
            "key_exchanged": self._key_exchanged,
            "mss": self._mss,
            "timestamp": time.time()
        })).decode("utf-8")

    @classmethod
    def loads(cls, s):
        try:
            s = pickle.loads(base64.b64decode(s))
            crypto = Crypto(s["crypto_key"], s["crypto_alg"])
            crypto._ensecret = tuple(s["crypto_ensecret"])
            crypto._desecret = tuple(s["crypto_desecret"])
            session = cls(s["session_id"], s["auth_key"], s["is_server"], crypto, s["mss"])
            session._current_crypto_key = s["current_crypto_key"]
            session._last_auth_time = int(s.get("last_auth_time", 0))
            session._key_exchanged = s.get("key_exchanged", True)
            if not s["is_server"] and not session._key_exchanged:
                return None
        except:
            return None
        return session

    def get_last_auth_time(self):
        return self._last_auth_time

    def set_last_auth_time(self, last_auth_time):
        if last_auth_time < self._last_auth_time:
            return

        self._last_auth_time = last_auth_time

    def get_encrypt_crypto(self, crypto_time):
        self._crypto.init_encrypt(crypto_time, self._crypto_ensecret, self._current_crypto_key)
        return self._crypto

    def get_decrypt_crypto(self, crypto_time):
        self._crypto.init_decrypt(crypto_time, self._crypto_desecret, self._current_crypto_key)
        return self._crypto

    def update_mss(self):
        self._mss = StreamFrame.FRAME_LEN

        for connection in self._connections:
            try:
                mss = min((connection._connection._socket.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG) or 1455) * 2
                          - StreamFrame.HEADER_LEN, StreamFrame.FRAME_LEN)
                if mss < self._mss:
                    self._mss = mss if mss > 2793 else StreamFrame.FRAME_LEN
            except Exception as e:
                logging.info("xstream update mss error %s", e)

    def add_connection(self, conn):
        if self._status == STATUS_CLOSED:
            conn.close()
        else:
            for connection in self._connections:
                if conn.crypto_time == connection._connection.crypto_time:
                    return None

            connection = Connection(conn, self)
            self._connections.append(connection)
            self._center.add_connection(connection)

            self.update_mss()

            return connection
        return None

    def remove_connection(self, conn):
        connection = None
        for connection in self._connections:
            if connection._connection == conn:
                if self._center:
                    self._center.remove_connection(connection)
                self._connections.remove(connection)

                self._rdata_len += connection._rdata_len
                self._wdata_len += connection._wdata_len
                self._rpdata_count += connection._rpdata_count
                self._wpdata_count += connection._wpdata_count
                self._rfdata_count += connection._rfdata_count
                self._wfdata_count += connection._wfdata_count
                break

        if not self._connections:
            if self._status == STATUS_CLOSED:
                if self._center:
                    self._center.close()
                    self._center = None
                    self.emit_close(self)
                    self.remove_all_listeners()
            else:
                def on_exit():
                    if not self._connections:
                        self.do_close()

                if self._status == STATUS_OPENING:
                    current().add_timeout(15 * 60, on_exit)
                else:
                    current().add_async(on_exit)

        self.update_mss()
        return connection

    def on_frame(self, center, frame):
        self._data_time = frame.recv_time
        if frame.action == 0:
            if not frame.data:
                return
            if self._status == STATUS_CLOSED:
                return

            stream_frame = frame.data
            stream_frame.recv_time = frame.recv_time
            if stream_frame.stream_id not in self._streams:
                if stream_frame.flag & 0x02 != 0:
                    priority, capped = 0, False
                    if stream_frame.flag & 0x10 != 0:
                        priority = 1
                    if stream_frame.flag & 0x20 != 0:
                        capped = True
                    if stream_frame.flag & 0x40 != 0:
                        self.create_stream(stream_frame.stream_id, priority=priority, capped=capped, expried_time=0)
                    else:
                        self.create_stream(stream_frame.stream_id, priority=priority, capped=capped)
                elif stream_frame.flag & 0x04 != 0:
                    data = rand_string(random.randint(1, 64))
                    frame = StreamFrame(stream_frame.stream_id, 0x04, 0, data)
                    frame.send_time = time.time()
                    self.write(frame)
            else:
                if stream_frame.flag & 0x02 != 0:
                    return self._streams[stream_frame.stream_id].close()

            if stream_frame.stream_id in self._streams:
                self._streams[stream_frame.stream_id].on_frame(stream_frame)
        else:
            self.on_action(frame.action, frame.data)

    def on_controll_data(self, stream, buffer):
        data = buffer.next()
        while data:
            self.on_action(data[0], data[1:])
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

    def create_stream(self, stream_id=None, **kwargs):
        is_server = stream_id is not None
        if stream_id is None:
            stream_id = self.get_stream_id()
        stream = Stream(stream_id, self, is_server, **kwargs)
        self._streams[stream_id] = stream
        self.emit_stream(self, stream)
        return stream

    def stream(self, callback=None, **kwargs):
        stream = self.create_stream(**kwargs)
        if callable(callback):
            callback(self, stream)
        if self._status == STATUS_CLOSED:
            current().add_async(stream.do_close)
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
                current().add_async(stream.do_close)
            return False
        return self._center.ready_write(stream, is_ready)

    def write(self, frame):
        if self._status == STATUS_CLOSED:
            if frame.stream_id in self._streams:
                current().add_async(self._streams[frame.stream_id].do_close)
            return False
        
        self._data_time = frame.send_time
        return self._center.write(frame)

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
        elif action == ACTION_KEYEXCHANGE:
            key_exchange_type, key_exchanged_count = struct.unpack("!BI", data[:5])
            if key_exchanged_count < self._key_exchanged_count:
                logging.info("xstream session %s error key exchange", self)
                return

            if key_exchange_type == 1:
                data = struct.pack("!BI", 2, self._key_exchanged_count) + rand_string(64)
                self.write_action(ACTION_KEYEXCHANGE, data, False)
                self._key_exchanged = False
                self.emit_keyexchange(self)
                logging.info("xstream session %s start %s key exchange", self, self._key_exchanged_count)
                return

            if key_exchange_type == 2:
                self._current_crypto_key = data[5:69]
                data = struct.pack("!BI", 3, self._key_exchanged_count) + self._current_crypto_key
                self.write_action(ACTION_KEYEXCHANGE, data, False)
                self._key_exchanged = True
                self._key_exchanged_count += 1
                self._key_exchanged_time = time.time()
                self.emit_keyexchange(self)
                logging.info("xstream session %s finish %s key exchange", self, self._key_exchanged_count - 1)
                return

            self._current_crypto_key = data[5:69]
            self._key_exchanged = True
            self._key_exchanged_count += 1
            self._key_exchanged_time = time.time()
            self.emit_keyexchange(self)
            logging.info("xstream session %s finish %s key exchange", self, self._key_exchanged_count - 1)

    def write_action(self, action, data=b'', index=None, center=False):
        if self._status == STATUS_CLOSED:
            return

        if not index:
            return self._center.write_action(action | 0x80, data, 0)
        else:
            data += rand_string(random.randint(1, 256))
            action = struct.pack("!B", action if center else action | 0x80)
            self._controll_stream.write(action + data)

    def start_key_exchange(self):
        if not self._key_exchanged:
            return False

        if not self._center or self._center.ttl > 500:
            return False

        data = struct.pack("!BI", 1, self._key_exchanged_count)
        self.write_action(ACTION_KEYEXCHANGE, data, False)
        self._key_exchanged = False
        self.emit_keyexchange(self)
        logging.info("xstream session %s start %s key exchange", self, self._key_exchanged_count)
        return True

    def close(self):
        if self._status == STATUS_CLOSED:
            return
        
        self._status = STATUS_CLOSED
        if not self._streams:
            return self.do_close()
            
        for stream_id, stream in tuple(self._streams.items()):
            stream.do_close()

    def do_close(self):
        if self._center is None:
            return

        self._status = STATUS_CLOSED
        if self._connections:
            for connection in self._connections:
                if connection._connection and connection._connection._state == tcp.STATE_CLOSED:
                    current().add_async(self.remove_connection, connection._connection)
                else:
                    connection.close()
        else:
            self._center.close()
            self._center = None
            self.emit_close(self)
            self.remove_all_listeners()
        logging.info("xstream session %s close", self)

    def get_ttl_info(self):
        rdata_len, wdata_len = self._rdata_len, self._wdata_len
        address = []
        for connection in self._connections:
            rdata_len += connection._rdata_len
            wdata_len += connection._wdata_len
            address.append((connection._connection.address, "%.2fms" % connection._ttl))
        return "%s %s %s" % (format_data_len(rdata_len), format_data_len(wdata_len), address)

    def __del__(self):
        self.close()

    def __str__(self):
        return "<%s %s,%s,%s,%s,%dms>" % (super(Session, self).__str__(), self._session_id, self._mss,
                                          len(self._connections), len(self._streams),
                                          self._center.ttl if self._center else 0)
