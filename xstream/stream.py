# -*- coding: utf-8 -*-
#14-4-22
# create by: snower

import time
import bson
import bisect
import logging
import struct
from ssloop import EventEmitter
from frame import Frame

SYN_STREAM=0x01
SYN_REPLY=0x02
SYN_FIN=0x03
SYN_CLOSE=0x04

class BaseStream(EventEmitter):
    class STATUS:
        INITED=1
        CONNECTING=2
        CONNECTED=3
        STREAMING=4
        CLOSING=5
        CLOSED=6

    def __init__(self,session,stream_id):
        super(BaseStream,self).__init__()
        self._stream_id=stream_id
        self._session=session
        self._frames=[]
        self._frame_id=1
        self._current_frame_id=1
        self._fin_frame_id=0
        self._last_recv_time=time.time()
        self._last_data_time=time.time()
        self._status=self.STATUS.INITED
        self.last_write_connection_id=0

    @property
    def id(self):
        return self._stream_id

    def streaming(self):
        self._status=self.STATUS.STREAMING
        self.emit("streaming",self)

    def write(self,data):
        if self._status!=self.STATUS.STREAMING:
            return False
        for i in xrange(int(len(data)/Frame.FRAME_LEN)+1):
            frame=Frame(data[i*Frame.FRAME_LEN:(i+1)*Frame.FRAME_LEN],self._session.id,self._stream_id,self._frame_id)
            self._session.write(self,frame)
            if self._frame_id==0xffffffff:
                self._frame_id=0
            self._frame_id+=1
        return len(data)

    def on_frame(self,frame):
        if frame.frame_id==0:
            self.control(frame)
            return
        self._last_recv_time=time.time()
        data=[]
        if frame.frame_id==self._current_frame_id:
            self._current_frame_id+=1
            data.append(frame.data)
        else:
            bisect.insort(self._frames,frame)

        while self._frames and self._frames[0].frame_id==self._current_frame_id:
            frame=self._frames.pop(0)
            data.append(frame.data)
            self._current_frame_id+=1
        if data:
            self._last_data_time=time.time()
            self.emit("data",self,"".join(data))
            if self._status==self.STATUS.CLOSING and self._fin_frame_id and self._fin_frame_id==self._current_frame_id:
                self.do_close()

    def open(self):
        pass

    def close(self):
        pass

    def control(self,frame):
        pass

    def write_control(self,type,data=''):
        data=struct.pack("B",type)+data
        frame=Frame(data,self._session.id,self._stream_id,0)
        self._session.write(self,frame)

    def loop(self):
        if time.time()-self._last_recv_time>300:
            self.close()

    def do_close(self):
        self._status=self.STATUS.CLOSED
        if self._session.close_stream(self):
            self.emit("close",self)
            logging.debug("xstream session %s stream %s close",self._session.id,self._stream_id)

class Stream(BaseStream):
    def __init__(self,session,stream_id):
        super(Stream,self).__init__(session,stream_id)

        self.open()

    def open(self):
        if self._status!=self.STATUS.INITED:return
        self._status=self.STATUS.CONNECTED
        self._session.open_stream(self)
        self.streaming()

    def close(self):
        if self._status==self.STATUS.CLOSED:return
        self.write_control(SYN_FIN,bson.dumps({"frame_id":self._frame_id}))
        self.do_close()

    def control(self,frame):
        type=ord(frame.data[0])
        if type==SYN_FIN:
            self._fin_frame_id=bson.loads(frame.data[1:])["frame_id"]
            if self._current_frame_id==self._fin_frame_id:
                self.do_close()
            else:
                self._status=self.STATUS.CLOSING

class StrictStream(BaseStream):
    def __init__(self,session,stream_id):
        super(StrictStream,self).__init__(session,stream_id)

    def open(self):
        if self._status!=self.STATUS.INITED:return
        self._status=self.STATUS.CONNECTING
        self._session.open_stream(self)
        self.write_control(SYN_STREAM)

    def close(self):
        if self._status==self.STATUS.CLOSED:return
        self._status=self.STATUS.CLOSING
        self.write_control(SYN_FIN,bson.dumps({"frame_id":self._frame_id}))

    def control(self,frame):
        type=ord(frame.data[0])
        if type==SYN_STREAM:
            self._status=self.STATUS.CONNECTED
            self._session.open_stream(self)
            self.write_control(SYN_REPLY)
            self.streaming()
        elif type==SYN_REPLY:
            self._status=self.STATUS.CONNECTED
            self.streaming()
        elif type==SYN_FIN:
            self.write_control(SYN_CLOSE,bson.dumps({"frame_id":self._frame_id}))
            self._fin_frame_id=bson.loads(frame.data[1:])["frame_id"]
            if self._current_frame_id==self._fin_frame_id:
                self.do_close()
            else:
                self._status=self.STATUS.CLOSING
        elif type==SYN_CLOSE:
            self._fin_frame_id=bson.loads(frame.data[1:])["frame_id"]
            if self._current_frame_id==self._fin_frame_id:
                self.do_close()