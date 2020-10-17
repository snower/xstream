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
        self.timestamp = 0 #((int(time.time() * 1000) & 0xffffffff0000) | (timestamp & 0xffff)) if timestamp is not None else int(time.time() * 1000)
        self.action = action
        self.data = data
        self.connection = connection
        self.send_time = 0
        self.recv_time = 0
        self.ack_time = 0
        self.resend_time = 0
        self.resend_count = 0
        self.send_timeout_count = 0

    def dumps(self):
        if self.data.__class__ == StreamFrame:
            return b"".join([struct.pack("!BHBIHBHBB", self.version, self.session_id, self.flag, self.index, self.timestamp & 0xffff, self.action,
                                        self.data.stream_id, self.data.flag, self.data.action), self.data.data])
        return b"".join([struct.pack("!BHBIHB", self.version, self.session_id, self.flag, self.index, self.timestamp & 0xffff, self.action), self.data])

    @classmethod
    def loads(cls, data, connection=None):
        if data[11] == 0 and len(data) >= 16:
            unpack_data = struct.unpack("!BHBIHBHBB", data[1:16])
            stream_frame = StreamFrame(*unpack_data[6:], data=data[16:])
            return Frame(*unpack_data[:6], data=stream_frame, connection=connection)
        return Frame(*struct.unpack("!BHBIHB", data[1:12]), data=data[12:], connection=connection)

    def __cmp__(self, other):
        return cmp(self.index, other.index)
    
    def __eq__(self, other):
        return self.index == other.index

    def __gt__(self, other):
        return self.index > other.index

    def __lt__(self, other):
        return self.index < other.index

    def __ge__(self, other):
        return self.index >= other.index

    def __le__(self, other):
        return self.index <= other.index

    def __ne__(self, other):
        return self.index != other.index

    def __len__(self):
        if self.data.__class__ == StreamFrame:
            return len(self.data.data) + 15
        return len(self.data) + 11

    def ttl(self):
        return int(time.time() * 1000) - self.timestamp

    def close(self):
        self.data = b''

class StreamFrame(object):
    HEADER_LEN = 23
    FRAME_LEN = 1440 * 2 - HEADER_LEN

    def __init__(self, stream_id, flag, action, data):
        self.stream_id = stream_id
        self.flag = flag
        self.action = action
        self.data = data
        self.send_time = 0
        self.recv_time = 0

    def dumps(self):
        return b"".join([struct.pack("!HBB", self.stream_id, self.flag, self.action), self.data])

    @classmethod
    def loads(cls, data):
        if data.__class__ == StreamFrame:
            return data
        return StreamFrame(*struct.unpack("!HBB", data[:4]), data=data[4:])

    def __len__(self):
        return len(self.data) + 4
