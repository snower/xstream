# -*- coding: utf-8 -*-
#14-4-22
# create by: snower

import time
import bson
import bisect
import logging
import struct
import math
from ssloop import EventEmitter
from frame import Frame

SYN_STREAM=0x01
SYN_REPLY=0x02
SYN_ACK=0x003
SYN_FIN=0x04
SYN_CLOSE=0x05

class BaseStream(EventEmitter):
    class STATUS:
        INITED=1
        CONNECTING=2
        CONNECTED=3
        STREAMING=4
        CLOSING=5
        CLOSED=6

    def __init__(self,session,stream_id,time_out=300):
        super(BaseStream,self).__init__()
        self._stream_id=stream_id
        self._session=session
        self._time_out=time_out
        self._frames=[]
        self._frame_id=1
        self._current_frame_id=1
        self._fin_frame_id=None
        self._last_recv_time=time.time()
        self._last_data_time=time.time()
        self._last_write_time=time.time()
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
            frame=Frame(self._session.id,self._stream_id,self._frame_id,data[i*Frame.FRAME_LEN:(i+1)*Frame.FRAME_LEN])
            self.write_frame(frame)
            self._frame_id+=1
        self._last_write_time=time.time()
        return len(data)

    def write_frame(self,frame):
        self._session.write(self,frame)

    def on_frame(self,frame):
        if frame.frame_id==0:
            self.control(frame)
            return
        self.on_data(frame)

    def on_data(self,frame):
        self._last_recv_time=time.time()
        if frame.frame_id<self._current_frame_id:return

        data=[]
        if frame.frame_id==self._current_frame_id:
            self._current_frame_id+=1
            data.append(frame.data)
        else:
            bisect.insort(self._frames,frame)
            return

        while self._frames:
            if self._frames[0].frame_id<self._current_frame_id:
                self._frames.pop(0)
                continue
            if self._frames[0].frame_id!=self._current_frame_id:break
            frame=self._frames.pop(0)
            data.append(frame.data)
            self._current_frame_id+=1

        if data:
            self._last_data_time=time.time()
            self.emit("data",self,"".join(data))

    def open(self):
        pass

    def close(self):
        pass

    def control(self,frame):
        pass

    def write_control(self,type,data=''):
        data=struct.pack("!B",type)+data
        frame=Frame(self._session.id,self._stream_id,0,data)
        self.write_frame(frame)

    def loop(self):
        if self._status==self.STATUS.CLOSING and self._fin_frame_id==self._current_frame_id:
            self.write_control(SYN_CLOSE)
            self.do_close()
        elif time.time()-max(self._last_write_time,self._last_recv_time)>self._time_out:
            self.do_close()

    def do_close(self):
        self._status=self.STATUS.CLOSED
        if self._session.close_stream(self):
            self.emit("close",self)
            self.remove_all_listeners()
            logging.debug("xstream session %s stream %s close",self._session.id,self._stream_id)

class Stream(BaseStream):
    def __init__(self,*args,**kwargs):
        super(Stream,self).__init__(*args,**kwargs)

        self._wlen=0
        self._wframes={}
        self._last_ack_time=0
        self.open()

    def write_frame(self,frame):
        super(Stream,self).write_frame(frame)
        if  frame.frame_id!=0:
            if self._wlen<131072:
                self._session.write(self,frame,True)
            self._wframes[frame.frame_id]=frame
            self._wlen+=len(frame.data)

    def open(self):
        if self._status!=self.STATUS.INITED:return
        self._status=self.STATUS.CONNECTED
        self._session.open_stream(self)
        self.streaming()

    def close(self):
        if self._status==self.STATUS.CLOSED:return
        self.write_control(SYN_FIN,struct.pack('!Q',self._frame_id))
        self._status=self.STATUS.CLOSING

    def do_close(self):
        self._wframes={}
        super(Stream,self).do_close()

    def control(self,frame):
        type=ord(frame.data[0])
        if type==SYN_ACK:
            frame_id,rewrite=struct.unpack("!QB",frame.data[1:])
            if rewrite:
                if frame_id in self._wframes:
                    super(Stream,self).write_frame(self._wframes[frame_id])
            else:
                for fid in self._wframes.keys():
                    if fid < frame_id:
                        del self._wframes[fid]
        elif type==SYN_FIN:
            self._fin_frame_id=struct.unpack("!Q",frame.data[1:])[0]
            if self._current_frame_id==self._fin_frame_id:
                self.write_control(SYN_CLOSE)
                self.do_close()
            else:
                self._status=self.STATUS.CLOSING
        elif type==SYN_CLOSE:
            self.do_close()

    def loop(self):
        if self._current_frame_id!=1:
            now=time.time()
            if now-self._last_data_time>=2 and self._frames and now-self._last_ack_time>=2:
                self.write_control(SYN_ACK,struct.pack("!QB",self._current_frame_id,1))
                self._last_ack_time=now
            elif now-self._last_ack_time>1 and now-self._last_data_time<2:
                self.write_control(SYN_ACK,struct.pack("!QB",self._current_frame_id,0))
                self._last_ack_time=now
        return super(Stream,self).loop()

class StrictStream(BaseStream):
    def __init__(self,*args,**kwargs):
        super(StrictStream,self).__init__(*args,**kwargs)

        self._wframes={}

    def write_frame(self,frame):
        super(StrictStream,self).write_frame(frame)
        if frame.frame_id!=0:
            self._wframes[frame.frame_id]=[frame,time.time(),5+math.sqrt(len(self._wframes))]

    def on_data(self,frame):
        self.write_control(SYN_ACK,bson.dumps({"frame_id":frame.frame_id}))
        return super(StrictStream,self).on_data(frame)

    def open(self):
        if self._status!=self.STATUS.INITED:return
        self._status=self.STATUS.CONNECTING
        self._session.open_stream(self)
        self.write_control(SYN_STREAM)

    def close(self):
        if self._status==self.STATUS.CLOSED:return
        self._status=self.STATUS.CLOSING
        self.write_control(SYN_FIN,bson.dumps({"frame_id":self._frame_id}))

    def do_close(self):
        self._wframes={}
        super(StrictStream,self).do_close()

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
        elif type==SYN_ACK:
            frame_id=bson.loads(frame.data[1:])["frame_id"]
            if frame_id in self._wframes:
                del self._wframes[frame_id]
        elif type==SYN_FIN:
            self._fin_frame_id=bson.loads(frame.data[1:])["frame_id"]
            if self._current_frame_id==self._fin_frame_id:
                self.write_control(SYN_CLOSE)
                self.do_close()
            else:
                self._status=self.STATUS.CLOSING
        elif type==SYN_CLOSE:
            self.do_close()

    def loop(self):
        now=time.time()
        for frame_id,frame in self._wframes.iteritems():
            if now-frame[1]>frame[2]+180:
                del self._wframes[frame_id]
            elif now-frame[1]>frame[2]:
                super(StrictStream,self).write_frame(frame[0])
                frame[2] +=5
        return super(StrictStream,self).loop()