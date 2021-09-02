# -*- coding: utf-8 -*-
#14-4-24
# create by: snower

import time
import logging
import random
import struct
import socket
from sevent import EventEmitter, current
from sevent.errors import SocketClosed
from .crypto import rand_string
from .utils import format_data_len
from .frame import Frame, StreamFrame

ACTION_CLOSE = 0x03
ACTION_CLOSE_ACK = 0x04
ACTION_READY = 0x05
ACTION_NOISE = 0x06
ACTION_PING = 0x11
ACTION_PINGACKPING = 0x12
ACTION_PINGACK = 0x13
ACTION_PINGACKACK = 0x14

class Connection(EventEmitter):
    FRAME_STRUCT = struct.Struct("!BBII")
    STREAM_FRAME_STRUCT = struct.Struct("!BBIIHBI")
    LEN_STRUCT = struct.Struct("!H")

    def __init__(self, connection, session):
        super(Connection, self).__init__()
        self.loop = current()
        self._connection = connection
        self._session = session
        self._crypto = connection.crypto

        try:
            connection.socket.setsockopt(socket.SOL_SOCKET, socket.TCP_KEEPINTVL, 0)
        except: pass

        self._connection.on_close(self.on_close)
        self._connection.on_data(self.on_data)
        self._connection.on_drain(self.on_drain)

        self._read_header = False
        self._start_time = time.time()
        self._brdata_len = 5
        self._bwdata_len = 0
        self._wait_head = True
        self._closed = False
        self._finaled = False
        self._data_time = time.time()
        self._ping_time = 0
        self._ping_ack_time = 0
        self._ping_timer = None
        self._ping_delayed_count = 0
        self._ttl = 0
        self._rdata_len = 0
        self._wdata_len = 0
        self._rpdata_count = 0
        self._wpdata_count = 0
        self._rfdata_count = 0
        self._wfdata_count = 0
        self._rlast_index = 0
        self._wlast_index = 0
        self._expried_seconds = random.randint(180, 1800)
        self._expried_seconds_timer = None
        self._expried_data = random.randint(8 * 1024 * 1024, 16 * 1024 * 1024)
        self._expried_data_timer = None
        self._close_timeout_timer = None

    def start(self):
        self.loop.add_async(self.emit_drain, self)

    def on_data(self, connection, buffer):
        if not self._read_header:
            if len(buffer) < 51:
                return
            buffer.read(51)
            self._read_header = True

        self._data_time = time.time()
        self._rpdata_count += 1
        if buffer._len >= self._brdata_len:
            self.read(buffer)

    def on_drain(self, connection):
        self.emit_drain(self)

    def on_close(self, connection):
        self.emit_close(self)
        self._closed = True
        self._session, session = None, self._session
        self.remove_all_listeners()
        if self._ping_timer:
            self.loop.cancel_timeout(self._ping_timer)
            self._ping_timer = None
        if self._expried_seconds_timer:
            self.loop.cancel_timeout(self._expried_seconds_timer)
            self._expried_seconds_timer = None
        if self._expried_data_timer:
            self.loop.cancel_timeout(self._expried_data_timer)
            self._expried_data_timer = None
        if self._close_timeout_timer:
            self.loop.cancel_timeout(self._close_timeout_timer)
            self._close_timeout_timer = None
        logging.info("xstream session %s connection %s close %.2fs %s %s %s %s %s %s", session, self,
                     time.time() - self._start_time, 
                     format_data_len(self._rdata_len), self._rfdata_count, self._rpdata_count,
                     format_data_len(self._wdata_len), self._wfdata_count, self._wpdata_count)

    def read(self, buffer):
        while buffer._len >= self._brdata_len:
            data = buffer.read(self._brdata_len)
            if self._wait_head:
                self._wait_head = False
                self._brdata_len, = self.LEN_STRUCT.unpack(data[3:])
            else:
                self._wait_head = True
                self._brdata_len = 5
                data = self._crypto.decrypt(data)

                if data[0] == 0:
                    if data[1] == 0 and len(data) >= 17:
                        unpack_data = Frame.STREAM_FRAME_STRUCT.unpack(data[1:17])
                        stream_frame = StreamFrame(*unpack_data[3:], data=data[17:])
                        frame = Frame(*unpack_data[:3], data=stream_frame, connection=self)
                    else:
                        frame = Frame(*Frame.FRAME_STRUCT.unpack(data[1:10]), data=data[10:], connection=self)
                    self._rlast_index = frame.index or self._rlast_index
                    self.emit_frame(self, frame)
                    self._rfdata_count += 1
                else:
                    self.on_action(data[0], data[1:])
                self._rdata_len += len(data) + 5

    def write(self, data):
        if data.__class__ == Frame:
            if data.index > 0:
                self._wlast_index = data.index
            if data.data.__class__ == StreamFrame:
                data = self._crypto.encrypt(self.STREAM_FRAME_STRUCT.pack(0, data.action, data.index, data.ack,
                                                        data.data.stream_id, data.data.flag,
                                                        data.data.index) + data.data.data)
            else:
                data = self._crypto.encrypt(self.FRAME_STRUCT.pack(0, data.action, data.index, data.ack) + data.data)
        else:
            data = self._crypto.encrypt(b'\x00' + data)
        data = b"".join([b'\x17\x03\x03', self.LEN_STRUCT.pack(len(data)), data])
        self._wdata_len += len(data)
        self._wpdata_count += 1
        self._wfdata_count += 1
        try:
            self._connection.write(data)
        except SocketClosed:
            return False
        return True

    def write_action(self, action, data=b''):
        data += rand_string(random.randint(64, 256))
        data = self._crypto.encrypt(struct.pack("!B", action) + data)
        data = b"".join([b'\x17\x03\x03', struct.pack("!H", len(data)), data])
        self._wdata_len += len(data)
        self._wpdata_count += 1
        self._wfdata_count += 1
        try:
            self._connection.write(data)
        except SocketClosed:
            return False
        return True

    def on_action(self, action, data):
        if action == ACTION_PING:
            self.write_action(ACTION_PINGACKPING)
            self._ping_time = time.time()
            self._ping_ack_time = 0
        elif action == ACTION_PINGACKPING:
            self.write_action(ACTION_PINGACK)
            self._ping_ack_time = time.time()
            self._ttl = (self._ping_ack_time - self._ping_time) * 1000
            logging.info("xstream session %s connection %s ping %.2fms", self._session, self, self._ttl)
            self.check_ping_delayed()
        elif action == ACTION_PINGACK:
            self.write_action(ACTION_PINGACKACK)
            self._ping_ack_time = time.time()
            self._ttl = (self._ping_ack_time - self._ping_time) * 1000
            logging.info("xstream session %s connection %s ping %.2fms", self._session, self, self._ttl)
            self.check_ping_delayed()
        elif action == ACTION_PINGACKACK:
            pass
        elif action == ACTION_CLOSE:
            self._closed = True
            self._finaled = True
            self.write_action(ACTION_CLOSE_ACK)
        elif action == ACTION_CLOSE_ACK:
            self._closed = True
            self._finaled = True
            self._connection.end()
            self.remove_all_listeners()
        elif action == ACTION_READY:
            self.write_action(ACTION_NOISE, rand_string(random.randint(16, 128)))
            logging.info('xstream session %s connection ready', self)

    def on_expried(self):
        if self._closed:
            return

        self.close()
        logging.info("xstream session %s connection %s expried timeout", self._session, self)

    def on_ping_loop(self, reping_timeout=0):
        if self._closed:
            return

        if reping_timeout <= 0:
            reping_timeout = random.randint(240, 300)

        session_ttl = self._session._center.ttl
        if session_ttl <= 400:
            timeout = reping_timeout
        elif session_ttl <= 800:
            timeout = 120
        elif session_ttl <= 1800:
            timeout = 60
        elif session_ttl <= 3000:
            timeout = 30
        elif session_ttl <= 4000:
            timeout = 20
        else:
            timeout = 15

        if self._ttl > 4000:
            timeout = min(30, timeout)
        elif self._ttl > 8000:
            timeout = min(15, timeout)

        session_delayed = (session_ttl >= 3000) if len(self._session._connections) <= 2 else (session_ttl >= 1000)
        if self._ttl <= 0 or time.time() - self._data_time >= reping_timeout \
            or (time.time() - self._ping_time >= timeout and (self._ttl > 3000 or session_delayed)):
            self.write_action(ACTION_PING)
            self._ping_time = time.time()
            self._ping_ack_time = 0
            self._ping_timer = current().add_timeout(5, self.on_ping_timeout)
        else:
            self._ping_timer = current().add_timeout(5, self.on_ping_loop, reping_timeout)

    def on_ping_timeout(self):
        if self._closed:
            return

        if self._ping_ack_time == 0:
            if time.time() - self._ping_time <= 15:
                self._ping_timer = current().add_timeout(5, self.on_ping_timeout)
                return
            self._closed = True
            self._connection.close()
            logging.info("xstream session %s connection %s ping timeout", self._session, self)
        else:
            self._ping_timer = current().add_timeout(5, self.on_ping_loop)

    def check_ping_delayed(self):
        if self._ttl > 4000:
            self._ping_delayed_count += 1
        elif self._ttl > 8000:
            self._ping_delayed_count += 2
        else:
            self._ping_delayed_count = 0
        if self._ping_delayed_count < 4:
            return
        self._closed = True
        self._connection.close()
        logging.info("xstream session %s connection %s ping delayed", self._session, self)

    def on_check_data_loop(self):
        if self._closed:
            return

        etime = time.time() - self._start_time
        if self._rdata_len + self._wdata_len <= self._expried_data:
            if self._rdata_len + self._wdata_len <= self._expried_data / 2.0 or etime < self._expried_seconds * 0.6:
                self._expried_data_timer = current().add_timeout(15, self.on_check_data_loop)
                return

        if etime < self._expried_seconds / 2.0:
            if etime < self._expried_seconds / (2.0 * float(self._rdata_len + self._wdata_len) / float(self._expried_data)):
                self._expried_data_timer = current().add_timeout(15, self.on_check_data_loop)
                return

        if not self._session.key_exchanged:
            self._expried_data_timer = current().add_timeout(15, self.on_check_data_loop)
            return

        self.close()
        logging.info("xstream session %s connection %s data len out", self._session, self)

    def close(self):
        if self._closed:
            return

        self._closed = True
        self.write_action(ACTION_CLOSE)
        self._close_timeout_timer = current().add_timeout(30, self._connection.close)

    def __del__(self):
        self.close()

    def __str__(self):
        return "<%s %s %.2fms>" % (super(Connection, self).__str__(), self._connection.address, self._ttl)