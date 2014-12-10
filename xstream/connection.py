# -*- coding: utf-8 -*-
#14-4-24
# create by: snower

import struct
from cStringIO import StringIO
from ssloop import EventEmitter

SYN_PING=0x01
SYN_CLOSING=0x02

class Connection(EventEmitter):
    def __init__(self, connection, session):
        super(Connection,self).__init__()
        self._connection = connection
        self._session = session

        self._connection.on("close",self.on_close)
        self._connection.on("data",self.on_data)
        self._connection.on("drain",self.on_drain)

        self._buffer_len = 0
        self._data_len = 2
        self._buffer = StringIO()
        self._wait_head = True
        self._closed = False

    def on_data(self, connection, data):
        self._buffer_len += len(data)
        self._buffer.write(data)
        self.read()

    def on_drain(self, connection):
        self.emit("drain", self)

    def on_close(self, connection):
        self.emit("close",self)
        self._connection=None
        self._closed = True
        self.remove_all_listeners()

    def read(self):
        if self._buffer_len >= self._data_len:
            buffer = StringIO(self._buffer.getvalue())
            while self._buffer_len >= self._data_len:
                self._buffer_len -= self._data_len
                if self._wait_head:
                    self._wait_head = False
                    self._data_len = struct.unpack("!H", buffer.read(self._data_len))[0]
                else:
                    self._wait_head = True
                    data = buffer.read(self._data_len)
                    self._buffer = StringIO()
                    if self._buffer_len > 0:
                        self._buffer.write(buffer.next())
                    self._data_len = 2
                    if data[-2:] != '\x0f\x0f':
                        continue

                    action = ord(data[0])
                    if action == 0:
                        self.emit("frame", self, data[1:-2])
                    else:
                        self.control(data[:-2])

    def write(self, data):
        data = "".join([struct.pack("!HB", len(data)+3, 0), data, '\x0f\x0f'])
        return self._connection.write(data)

    def control(self, data):
        pass
