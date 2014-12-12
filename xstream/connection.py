# -*- coding: utf-8 -*-
#14-4-24
# create by: snower

import time
import logging
import random
import struct
from collections import deque
from ssloop import EventEmitter, current

ACTION_PING = 0x01
ACTION_PINGACK = 0x02

class Buffer(object):
    def __init__(self):
        self._buffer = ''
        self._buffers = deque()
        self._len = 0
        self._index = 0

    def write(self, data):
        self._buffers.append(data)
        self._len += len(data)

    def read(self, size):
        if len(self._buffer) - self._index < size:
            self._buffer = self._buffer[self._index:] + "".join(self._buffers)
            self._index = 0
            self._buffers = deque()
        data = self._buffer[self._index: self._index + size]
        self._index += size
        self._len -= size
        return data

    def __len__(self):
        return self._len

class Connection(EventEmitter):
    def __init__(self, connection, session):
        super(Connection,self).__init__()
        self._connection = connection
        self._session = session

        self._connection.on("close",self.on_close)
        self._connection.on("data",self.on_data)
        self._connection.on("drain",self.on_drain)

        self._data_len = 2
        self._buffer = Buffer()
        self._wait_head = True
        self._closed = False
        self._data_time = time.time()
        self._ping_time = 0

        if not self._session._is_server:
            current().timeout(random.randint(300, 900), self.on_expried)
            current().timeout(30, self.on_ping_loop)

    def on_data(self, connection, data):
        self._buffer.write(data)
        self.read()
        self._data_time = time.time()

    def on_drain(self, connection):
        if not self._closed:
            self.emit("drain", self)

    def on_close(self, connection):
        self.emit("close",self)
        self._closed = True
        self._session = None
        self.remove_all_listeners()

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
                    continue

                action = ord(data[0])
                if action == 0:
                    self.emit("frame", self, data[1:-2])
                else:
                    self.on_action(action, data[1:-2])

    def write(self, data):
        if self._closed:
            return
        data = "".join([struct.pack("!HB", len(data)+3, 0), data, '\x0f\x0f'])
        return self._connection.write(data)

    def write_action(self, action, data=''):
        data = "".join([struct.pack("!HB", len(data)+3, action), data, '\x0f\x0f'])
        return self._connection.write(data)

    def on_action(self, action, data):
        if action == ACTION_PING:
            self.write_action(ACTION_PINGACK)
        elif action == ACTION_PINGACK:
            self._ping_time = time.time()

    def on_expried(self):
        if self._closed:
            return
        self._connection.close()
        logging.info("connection %s expried timeout", self)

    def on_ping_loop(self):
        if self._closed:
            return
        if time.time() - self._data_time >= 30:
            self.write_action(ACTION_PING)
            self._ping_time = 0
            current().timeout(30, self.on_ping_timeout)
        else:
            current().timeout(30, self.on_ping_loop)

    def on_ping_timeout(self):
        if self._closed:
            return
        if self._ping_time == 0:
            self._connection.close()
            logging.info("connection %s ping timeout", self)
        else:
            current().timeout(30, self.on_ping_loop)