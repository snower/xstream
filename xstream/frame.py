# -*- coding: utf-8 -*-
#14-4-22
# create by: snower

import struct

class Frame(object):
    def __init__(self, session_id, flag, index, stream_id, data):
        self.session_id = session_id
        self.flag = flag
        self.index = index
        self.stream_id = stream_id
        self.data = data

    def dumps(self):
        return "".join([struct.pack("!HBQH", self.session_id, self.flag, self.index, self.stream_id), self.data])

    @classmethod
    def loads(cls, data):
        return Frame(*struct.unpack("!HBQH", data[:13]), data=data[13:])