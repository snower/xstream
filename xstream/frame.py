# -*- coding: utf-8 -*-
#14-4-22
# create by: snower

import struct

class Frame(object):
    FRAME_LEN=0xffff-10
    def __init__(self,data,session_id=None,stream_id=None,frame_id=None):
        if session_id is not None and stream_id is not None and frame_id is not None:
            self.session_id=session_id
            self.stream_id=stream_id
            self.frame_id=frame_id
            self.data=data
        else:
            self.session_id=struct.unpack('H',data[:2])[0]
            self.stream_id=struct.unpack("H",data[2:4])[0]
            self.frame_id=struct.unpack("I",data[4:8])[0]
            self.data=data[8:]

    def get_data(self):
        return self.data

    def __cmp__(self, other):
        return cmp(self.frame_id,other.frame_id)

    def __str__(self):
        return "".join([struct.pack('H',self.session_id),struct.pack('H',self.stream_id),struct.pack('I',self.frame_id),self.data])