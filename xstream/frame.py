# -*- coding: utf-8 -*-
#14-4-22
# create by: snower

import time
import struct

class Frame(object):
    def __init__(self, version, session_id, flag, index, timestamp, action, data, connection=None):
        self.version = version
        self.session_id = session_id
        self.flag = flag
        self.index = index
        self.timestamp = ((int(time.time() * 1000) & 0xffffffff0000) | (timestamp & 0xffff)) if timestamp is not None else int(time.time() * 1000)
        self.action = action
        self.data = data
        self.connection = connection
        self.send_time = 0
        self.ack_time = 0

    def dumps(self):
        return "".join([struct.pack("!BHBIHB", self.version, self.session_id, self.flag, self.index, self.timestamp & 0xffff, self.action), self.data])

    @classmethod
    def loads(cls, data, connection=None):
        return Frame(*struct.unpack("!BHBIHB", data[:11]), data=data[11:], connection=connection)

    def __cmp__(self, other):
        return cmp(self.index, other.index)

    def ttl(self):
        return int(time.time() * 1000) - self.timestamp

    def close(self):
        self.data = ''

class StreamFrame(object):
    HEADER_LEN = 23
    FRAME_LEN = 1460 * 2 - HEADER_LEN

    def __init__(self, stream_id, flag, action, data):
        self.stream_id = stream_id
        self.flag = flag
        self.action = action
        self.data = data

    def dumps(self):
        return "".join([struct.pack("!HBB", self.stream_id, self.flag, self.action), self.data])

    @classmethod
    def loads(cls, data):
        return StreamFrame(*struct.unpack("!HBB", data[:4]), data=data[4:])

    def __len__(self):
        return len(self.data)
