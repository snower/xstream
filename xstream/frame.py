# -*- coding: utf-8 -*-
#14-4-22
# create by: snower

import time
import struct

class Frame(object):
    def __init__(self, action, index, ack, data, connection=None):
        self.action = action
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
            return b"".join([struct.pack("!BIIHBI", self.action, self.index, self.ack,
                                        self.data.stream_id, self.data.action, self.data.flag, self.data.index), self.data.data])
        return b"".join([struct.pack("!BII", self.action, self.index, self.ack), self.data])

    @classmethod
    def loads(cls, data, connection=None):
        if data[1] == 0 and len(data) >= 17:
            unpack_data = struct.unpack("!BIIHBI", data[1:17])
            stream_frame = StreamFrame(*unpack_data[3:], data=data[17:])
            return Frame(*unpack_data[:3], data=stream_frame, connection=connection)
        return Frame(*struct.unpack("!BII", data[1:10]), data=data[10:], connection=connection)

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
            return len(self.data.data) + 17
        return len(self.data) + 9

    def close(self):
        self.data = b''

class StreamFrame(object):
    HEADER_LEN = 22
    FRAME_LEN = 1455 * 2 - HEADER_LEN

    def __init__(self, stream_id, flag, index, data):
        self.stream_id = stream_id
        self.flag = flag
        self.index = index
        self.data = data
        self.send_time = 0
        self.recv_time = 0

    def dumps(self):
        return b"".join([struct.pack("!HBI", self.stream_id, self.flag, self.index), self.data])

    @classmethod
    def loads(cls, data):
        if data.__class__ == StreamFrame:
            return data
        return StreamFrame(*struct.unpack("!HBI", data[:7]), data=data[7:])

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
        return len(self.data) + 7
