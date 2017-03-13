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
from crypto import rand_string
from utils import format_data_len

ACTION_PING = 0x01
ACTION_PINGACK = 0x02
ACTION_CLOSE  = 0x03
ACTION_CLOSE_ACK = 0x04
ACTION_NOISE = 0x05

class Connection(EventEmitter):
    def __init__(self, connection, session, mss):
        super(Connection,self).__init__()
        self._connection = connection
        self._session = session
        self._crypto = connection.crypto
        self._mss = mss

        try:
            connection.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            connection.socket.setsockopt(socket.SOL_SOCKET, socket.TCP_KEEPINTVL, 0)
        except: pass

        self._connection.on("close",self.on_close)
        self._connection.on("data",self.on_data)
        self._connection.on("drain",self.on_drain)

        self._start_time = time.time()
        self._data_len = 2
        self._buffer = Buffer()
        self._wdata_len = 0
        self._wbuffer = deque()
        self._wait_head = True
        self._wait_write = False
        self._closed = False
        self._data_time = time.time()
        self._ping_time = 0
        self._rdata_count = 0
        self._wdata_count = 0

    def on_data(self, connection, data):
        self._data_time = time.time()
        if self._buffer._len + data._len >= self._data_len:
            data = self._crypto.decrypt(data.read(-1))
            self._rdata_count += len(data)
            self._buffer.write(data)
            self.read()

    def on_drain(self, connection):
        if not self._closed:
            self.emit("drain", self)

    def on_close(self, connection):
        self.emit("close",self)
        self._closed = True
        self._session, session = None, self._session
        self.remove_all_listeners()
        logging.info("xstream session %s connection %s close %.2fs %s %s", session, self,
                     time.time() - self._start_time, format_data_len(self._rdata_count), format_data_len(self._wdata_count))

    def read(self):
        while len(self._buffer) >= self._data_len:
            data = self._buffer.read(self._data_len)
            if self._wait_head:
                self._wait_head = False
                self._data_len, = struct.unpack("!H", data)
            else:
                self._wait_head = True
                self._data_len = 2

                if data[-2:] != '\x0f\x0f':
                    logging.info("xstream session %s connection %s verify error", self._session, self)
                    return self._connection.close()

                action = ord(data[0])
                if action == 0:
                    self.emit("frame", self, data[1:-2])
                else:
                    self.on_action(action, data[1:-2])

    def do_write(self):
        if not self._closed:
            data = self._crypto.encrypt("".join(self._wbuffer))
            self._wdata_count += len(data)
            self._connection.write(data)
            self._wbuffer.clear()
            self._wdata_len = 0
            self._wait_write = False

    def write(self, data):
        if not self._closed:
            data = "".join([struct.pack("!HB", len(data)+3, 0), data, '\x0f\x0f'])
            self._wbuffer.append(data)
            self._wdata_len += len(data)
            if not self._wait_write:
                current().async(self.do_write)
                self._wait_write = True
            return self._wdata_len < self._mss - 236

    def write_action(self, action, data=''):
        data += rand_string(random.randint(1, 256))
        data = "".join([struct.pack("!HB", len(data)+3, action), data, '\x0f\x0f'])
        data = self._crypto.encrypt(data)
        self._wdata_count += len(data)
        return self._connection.write(data)

    def on_action(self, action, data):
        if action == ACTION_PING:
            self.write_action(ACTION_PINGACK)
        elif action == ACTION_PINGACK:
            self._ping_time = time.time()
        elif action == ACTION_CLOSE:
            self._closed = True
            self.write_action(ACTION_CLOSE_ACK)
        elif action == ACTION_CLOSE_ACK:
            self._closed = True
            self._connection.close()
            self.remove_all_listeners()

    def on_expried(self):
        if not self._closed:
            self.close()
            logging.info("xstream session %s connection %s expried timeout", self._session, self)

    def on_ping_loop(self):
        if not self._closed:
            if time.time() - self._data_time >= 15:
                self.write_action(ACTION_PING)
                self._ping_time = 0
                current().timeout(2, self.on_ping_timeout)
            else:
                current().timeout(10, self.on_ping_loop)

    def on_ping_timeout(self):
        if not self._closed:
            if self._ping_time == 0:
                self._closed = True
                self._connection.close()
                logging.info("xstream session %s connection %s ping timeout", self._session, self)
            else:
                current().timeout(5, self.on_ping_loop)

    def close(self):
        if self._closed:
            self._connection.close()
            self.remove_all_listeners()
        else:
            self._closed = True
            self.write_action(ACTION_CLOSE)
            current().timeout(5, self._connection.close)

    def __del__(self):
        self.close()
