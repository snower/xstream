# -*- coding: utf-8 -*-
#14-4-24
# create by: snower

import time
import logging
import random
import struct
import socket
from collections import deque
from sevent import EventEmitter, current, Buffer
from sevent.errors import SocketClosed
from .crypto import rand_string
from .utils import format_data_len
from .frame import Frame, StreamFrame

ACTION_PING = 0x01
ACTION_PINGACK = 0x02
ACTION_CLOSE = 0x03
ACTION_CLOSE_ACK = 0x04
ACTION_READY = 0x05
ACTION_NOISE = 0x06

class Connection(EventEmitter):
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
        self._flush_buffer = deque()
        self._wait_head = True
        self._wait_read = False
        self._closed = False
        self._finaled = False
        self._data_time = time.time()
        self._ping_time = 0
        self._ping_ack_time = 0
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
        self._expried_data = random.randint(8 * 1024 * 1024, 16 * 1024 * 1024)
        current().add_timeout(15, self.on_check_data_loop)

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
        if not self._wait_read and buffer._len >= self._brdata_len:
            self._wait_read = True
            self.loop.add_async(self.read, buffer)

    def on_drain(self, connection):
        self.emit_drain(self)

    def on_close(self, connection):
        self.emit_close(self)
        self._closed = True
        self._session, session = None, self._session
        self.remove_all_listeners()
        logging.info("xstream session %s connection %s close %.2fs %s %s %s %s %s %s", session, self,
                     time.time() - self._start_time, 
                     format_data_len(self._rdata_len), self._rfdata_count, self._rpdata_count,
                     format_data_len(self._wdata_len), self._wfdata_count, self._wpdata_count)

    def read(self, buffer):
        self._wait_read = False
        read_count = 0
        while buffer._len >= self._brdata_len:
            data = buffer.read(self._brdata_len)
            if self._wait_head:
                self._wait_head = False
                self._brdata_len, = struct.unpack("!H", data[3:])
                if read_count >= 64:
                    if buffer._len >= self._brdata_len:
                        self._wait_read = True
                        self.loop.add_async(self.read, buffer)
                    break
            else:
                self._wait_head = True
                self._brdata_len = 5
                data = self._crypto.decrypt(data)

                if data[0] == 0:
                    if data[11] == 0 and len(data) >= 16:
                        unpack_data = struct.unpack("!BHBIHBHBB", data[1:16])
                        stream_frame = StreamFrame(*unpack_data[6:], data=data[16:])
                        frame = Frame(*unpack_data[:6], data=stream_frame, connection=self)
                    else:
                        frame = Frame(*struct.unpack("!BHBIHB", data[1:12]), data=data[12:], connection=self)
                    self._rlast_index = frame.index or self._rlast_index
                    self.emit_frame(self, frame)
                    self._rfdata_count += 1
                else:
                    self.on_action(data[0], data[1:])
                self._rdata_len += len(data) + 5
                read_count += 1

    def flush(self):
        if not self._closed:
            data = []
            while self._flush_buffer:
                feg = self._flush_buffer.popleft()
                if feg.__class__ == Frame:
                    self._wlast_index = feg.index or self._wlast_index
                    if feg.data.__class__ == StreamFrame:
                        feg = self._crypto.encrypt(b"".join([b'\x00', struct.pack("!BHBIHBHBB", feg.version, feg.session_id, feg.flag, feg.index,
                                                                                feg.timestamp & 0xffff, feg.action, feg.data.stream_id,
                                                                                feg.data.flag, feg.data.action), feg.data.data]))
                    else:
                        feg = self._crypto.encrypt(b"".join([b'\x00', struct.pack("!BHBIHB", feg.version, feg.session_id, feg.flag, feg.index,
                                                                                feg.timestamp & 0xffff, feg.action), feg.data]))
                else:
                    feg = self._crypto.encrypt(b"".join([b'\x00', feg]))

                data.append(b'\x17\x03\x03')
                data.append(struct.pack("!H", len(feg)))
                data.append(feg)

            data = b"".join(data)
            self._wdata_len += len(data)
            self._wpdata_count += 1
            try:
                self._connection.write(data)
            except SocketClosed:
                pass
            self._flush_buffer.clear()
            self._bwdata_len = 0

    def write(self, data):
        if not self._closed:
            self._flush_buffer.append(data)
            self._bwdata_len += len(data) + 8
            self._wfdata_count += 1
            return self._session._mss - self._bwdata_len
        return 0

    def write_action(self, action, data=b''):
        data += rand_string(random.randint(1, 128))
        data = self._crypto.encrypt(b"".join([struct.pack("!B", action), data]))
        data = b"".join([b'\x17\x03\x03', struct.pack("!H", len(data)), data])
        self._wdata_len += len(data)
        self._wpdata_count += 1
        self._wfdata_count += 1
        try:
            return self._connection.write(data)
        except SocketClosed:
            return False

    def on_action(self, action, data):
        if action == ACTION_PING:
            self.write_action(ACTION_PINGACK)
        elif action == ACTION_PINGACK:
            self._ping_ack_time = time.time()
            self._ttl = (self._ping_ack_time - self._ping_time) * 1000
            logging.info("xstream session %s connection %s ping ack", self._session, self)
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
        if not self._closed:
            self.close()
            logging.info("xstream session %s connection %s expried timeout", self._session, self)

    def on_ping_loop(self):
        if not self._closed:
            timeout = 180 if self._session._center.ttl <= 500 else (60 if self._session._center.ttl <= 1000 else 15)
            if self._ttl <= 0 or time.time() - self._data_time >= timeout \
                    or (len(self._session._connections) > 2 and time.time() - self._ping_time >= timeout
                        and self._session._center.ttl >= 1000):
                self.write_action(ACTION_PING)
                self._ping_time = time.time()
                self._ping_ack_time = 0
                current().add_timeout(5, self.on_ping_timeout)
                logging.info("xstream session %s connection %s ping", self._session, self)
            else:
                current().add_timeout(5, self.on_ping_loop)

    def on_ping_timeout(self):
        if not self._closed:
            if self._ping_ack_time == 0:
                if time.time() - self._ping_time < 30:
                    current().add_timeout(5, self.on_ping_timeout)
                    return
                self._closed = True
                self._connection.close()
                logging.info("xstream session %s connection %s ping timeout", self._session, self)
            else:
                current().add_timeout(5, self.on_ping_loop)

    def on_check_data_loop(self):
        if not self._closed:
            etime = time.time() - self._start_time
            if self._rdata_len <= self._expried_data:
                if self._rdata_len <= self._expried_data / 2.0 or etime < self._expried_seconds * 0.6:
                    return current().add_timeout(5, self.on_check_data_loop)

            if etime < self._expried_seconds / 2.0:
                if etime < self._expried_seconds / (2.0 * float(self._rdata_len) / float(self._expried_data)):
                    return current().add_timeout(5, self.on_check_data_loop)

            self.close()
            logging.info("xstream session %s connection %s data len out", self._session, self)

    def close(self):
        if not self._closed:
            self._closed = True
            self.write_action(ACTION_CLOSE)
            current().add_timeout(30, self._connection.close)

    def __del__(self):
        self.close()

    def __str__(self):
        return "<%s %s %.2fms>" % (super(Connection, self).__str__(), self._connection.address, self._ttl)