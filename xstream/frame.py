# -*- coding: utf-8 -*-
#14-4-22
# create by: snower

import struct

class Frame(object):
    FRAME_LEN=0xffff-10
    def __init__(self,data,session_id=None,stream_id=None,frame_id=None,flag=0x00):
        if session_id is not None and stream_id is not None and frame_id is not None:
            self.session_id=session_id
            self.stream_id=stream_id
            self.frame_id=frame_id
            self.flag=flag & 0xfc
            self.data=data
        else:
            self.session_id=struct.unpack('!H',data[:2])[0]
            self.stream_id=struct.unpack("!H",data[2:4])[0]
            self.flag=struct.unpack('!B',data[4])[0]
            frame_id_size,self.frame_id=self.unpack_frame_id(data)
            self.data=data[5+frame_id_size:]

    def pack_frame_id(self):
        if self.frame_id<=0xff:
            self.flag |=0x00
            return struct.pack('!B')
        elif self.frame_id<=0xffff:
            self.flag |=0x01
            return struct.pack('!H')
        elif self.frame_id<=0xffffffff:
            self.flag |=0x02
            return struct.pack('!I')
        self.flag |=0x03
        return struct.pack('!Q')

    def unpack_frame_id(self,data):
        self.flag &=0x03
        if self.flag==0x00:
            return 1,struct.unpack('!B',data[5])[0]
        elif self.flag==0x01:
            return 2,struct.unpack('!H',data[5:7])[0]
        elif self.flag==0x02:
            return 4,struct.unpack('!I',data[5:9])[0]
        return 8,struct.unpack('!Q',data[5:13])[0]

    def get_data(self):
        return self.data

    def __cmp__(self, other):
        return cmp(self.frame_id,other.frame_id)

    def __str__(self):
        frame_id=self.pack_frame_id()
        return "".join([struct.pack('!H',self.session_id),struct.pack('!H',self.stream_id),struct.pack('!B',self.flag),frame_id,self.data])