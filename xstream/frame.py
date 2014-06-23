# -*- coding: utf-8 -*-
#14-4-22
# create by: snower

import struct

class FrameException(Exception):pass
class FrameUnpackFinish(FrameException):
    def __init__(self,data):
        self.data=data

class FrameUnpackVerifyError(FrameException):
    def __init__(self,data):
        self.data=data

class Frame(object):
    FRAME_LEN=65489
    def __init__(self,session_id=None,stream_id=None,frame_id=None,data='',flag=0x00):
        self.version=0x10
        self.session_id=session_id
        self.stream_id=stream_id
        self.frame_id=frame_id
        self.flag=flag
        self.data=data
        self.verify='\x0f\x0f'

    def pack_session_id(self):
        if self.session_id<=0xff:
            return 'B'
        self.version |=0x08
        return 'H'

    def pack_stream_id(self):
        if self.stream_id<=0xff:
            return 'B'
        self.version |=0x04
        return 'H'

    def pack_frame_id(self):
        if self.frame_id<=0xff:
            return 'B'
        elif self.frame_id<=0xffff:
            self.version |=0x01
            return 'H'
        elif self.frame_id<=0xffffffff:
            self.version |=0x02
            return 'I'
        self.version |=0x03
        return 'Q'

    def unpack_version(self,data):
        if data:
            self.version=struct.unpack('!B',data[0])[0]
            self.unpack=self.unpack_session_id
            return self.unpack(data[1:])
        return data

    def unpack_session_id(self,data):
        if self.version & 0x08:
            if len(data)<2:return data
            self.session_id=struct.unpack('!H',data[:2])[0]
            data=data[2:]
        else:
            if not data:return data
            self.session_id=struct.unpack('!B',data[0])[0]
            data=data[1:]
        self.unpack=self.unpack_stream_id
        return self.unpack(data)

    def unpack_stream_id(self,data):
        if self.version & 0x04:
            if len(data)<2:return data
            self.stream_id=struct.unpack('!H',data[:2])[0]
            data=data[2:]
        else:
            if not data:return data
            self.stream_id=struct.unpack('!B',data[0])[0]
            data=data[1:]
        self.unpack=self.unpack_frame_id
        return self.unpack(data)

    def unpack_frame_id(self,data):
        if self.version & 0x03 ==0x00:
            if not data:return data
            self.frame_id=struct.unpack('!B',data[0])[0]
            data=data[1:]
        elif self.version & 0x03 ==0x01:
            if len(data)<2:return data
            self.frame_id=struct.unpack('!H',data[:2])[0]
            data=data[2:]
        elif self.version & 0x03 ==0x02:
            if len(data)<4:return data
            self.frame_id=struct.unpack('!I',data[:4])[0]
            data=data[4:]
        else:
            if len(data)<8:return data
            self.frame_id=struct.unpack('!Q',data[:8])[0]
            data=data[8:]
        self.unpack=self.unpack_flag
        return self.unpack(data)

    def unpack_flag(self,data):
        if data:
            self.flag=struct.unpack('!B',data[0])[0]
            self.unpack=self.unpack_data
            return self.unpack(data[1:])
        return data

    def unpack_data(self,data):
        if len(data)<2:return data
        dlen=struct.unpack('!H',data[:2])[0]
        if len(data)<dlen+2:return data
        self.data=data[2:dlen+2]
        self.unpack=self.unpack_verify
        return self.unpack(data[dlen+2:])

    def unpack_verify(self,data):
        if len(data)<2:return data
        if data[:2]!=self.verify:
            raise FrameUnpackVerifyError(data[2:])
        raise FrameUnpackFinish(data[2:])

    def pack(self):
        format="".join(['!B',self.pack_session_id(),self.pack_stream_id(),self.pack_frame_id(),'B','H',str(len(self.data)),'s','2s'])
        return struct.pack(format,self.version,self.session_id,self.stream_id,self.frame_id,self.flag,len(self.data),self.data,self.verify)

    unpack=unpack_version

    def __cmp__(self, other):
        return cmp(self.frame_id,other.frame_id)