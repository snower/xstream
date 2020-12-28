# -*- coding: utf-8 -*-
#14-4-22
# create by: snower

import time
import struct

class Frame(object):
    def __init__(self, action, flag, index, ack, data, connection=None):
        self.action = action
        self.flag = flag
        self.index = index
        self.ack = ack
        self.data = data
        self.connection = connection
        self.used_connections = set([])
        self.send_time = 0
        self.recv_time = 0
        self.ack_time = 0
        self.resend_time = 0
        self.resend_count = 0
        self.send_timeout_count = 0

    def dumps(self):
        if self.data.__class__ == StreamFrame:
            return b"".join([struct.pack("!BBIIHBBI", self.action, self.flag, self.index, self.ack,
                                        self.data.stream_id, self.data.action, self.data.flag, self.data.index), self.data.data])
        return b"".join([struct.pack("!BBII", self.action, self.flag, self.index, self.ack), self.data])

    @classmethod
    def loads(cls, data, connection=None):
        if data[11] == 0 and len(data) >= 16:
            unpack_data = struct.unpack("!BBIIHBBI", data[1:19])
            stream_frame = StreamFrame(*unpack_data[4:], data=data[19:])
            return Frame(*unpack_data[:6], data=stream_frame, connection=connection)
        return Frame(*struct.unpack("!BBII", data[1:11]), data=data[11:], connection=connection)

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
            return len(self.data.data) + 18
        return len(self.data) + 10

    def close(self):
        self.data = b''

class StreamFrame(object):
    HEADER_LEN = 25
    FRAME_LEN = 1455 * 2 - HEADER_LEN

    def __init__(self, stream_id, action, flag, index, data):
        self.action = action
        self.stream_id = stream_id
        self.flag = flag
        self.index = index
        self.data = data
        self.send_time = 0
        self.recv_time = 0

    def dumps(self):
        return b"".join([struct.pack("!HBBI", self.stream_id, self.action, self.flag, self.index), self.data])

    @classmethod
    def loads(cls, data):
        if data.__class__ == StreamFrame:
            return data
        return StreamFrame(*struct.unpack("!HBBI", data[:8]), data=data[8:])

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
        return len(self.data) + 8
