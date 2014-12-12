# -*- coding: utf-8 -*-
#14-4-24
# create by: snower

import struct
from collections import deque
from ssloop import EventEmitter

SYN_PING=0x01
SYN_CLOSING=0x02

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

    def on_data(self, connection, data):
        self._buffer.write(data)
        self.read()

    def on_drain(self, connection):
        self.emit("drain", self)

    def on_close(self, connection):
        self.emit("close",self)
        self._closed = True
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
        data = "".join([struct.pack("!HB", len(data)+3, 0), data, '\x0f\x0f'])
        return self._connection.write(data)

    def on_action(self, action, data):
        pass
