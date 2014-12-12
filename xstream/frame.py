# -*- coding: utf-8 -*-
#14-4-22
# create by: snower

import time
import struct

class Frame(object):
    def __init__(self, version, session_id, flag, index, timestamp, action, data):
        self.version = version
        self.session_id = session_id
        self.flag = flag
        self.index = index
        self.timestamp = timestamp if timestamp is not None else (int(time.time() * 1000) & 0xffff)
        self.action = action
        self.data = data

    def dumps(self):
        return "".join([struct.pack("!BHBQHB", self.version, self.session_id, self.flag, self.index, self.timestamp, self.action), self.data])

    @classmethod
    def loads(cls, data):
        return Frame(*struct.unpack("!BHBQHB", data[:15]), data=data[15:])

    def __cmp__(self, other):
        return cmp(self.index, other.index)

    def ttl(self):
        return (int(time.time() * 1000) & 0xffff) - self.timestamp

class StreamFrame(object):
    FRAME_LEN = 16 * 1024

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