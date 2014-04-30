# -*- coding: utf-8 -*-
#14-4-22
# create by: snower

import time
import json
import bisect
import logging
from ssloop import EventEmitter
from frame import Frame

class Stream(EventEmitter):
    class STATUS:
        CONNECTED=1
        CLOSED=2

    def __init__(self,session,stream_id):
        super(Stream,self).__init__()
        self._stream_id=stream_id
        self._session=session
        self._frames=[]
        self._frame_id=1
        self._current_frame_id=1
        self._last_recv_time=time.time()
        self._last_data_time=time.time()
        self._status=self.STATUS.CONNECTED

    @property
    def id(self):
        return self._stream_id

    def write(self,data):
        if self._status==self.STATUS.CLOSED:
            return False
        for i in xrange(int(len(data)/Frame.FRAME_LEN)+1):
            frame=Frame(data[i*Frame.FRAME_LEN:(i+1)*Frame.FRAME_LEN],self._session.id,self._stream_id,self._frame_id)
            self._session.write(frame)
            self._frame_id+=1
        return len(data)

    def on_frame(self,frame):
        if frame.frame_id==0:
            self.command(frame.data)
            return
        self._last_recv_time=time.time()
        if frame.frame_id==self._current_frame_id:
            self._current_frame_id+=1
            self._last_data_time=time.time()
            self.emit("data",self,frame.data)
            if not self._frames:return
        else:
            bisect.insort(self._frames,frame)

        data=[]
        while self._frames and self._frames[0].frame_id==self._current_frame_id:
            frame=self._frames.pop(0)
            data.append(frame.data)
            self._current_frame_id+=1
        if data:
            self._last_data_time=time.time()
            self.emit("data",self,"".join(data))

    def command(self,data):
        info=json.loads(data)
        if "action" in info and hasattr(self,"ctl_"+info["action"]):
            getattr(self,"ctl_"+info["action"])(info)

    def close(self):
        self._session.close_stream(self)
        info={"action":"close"}
        frame=Frame(json.dumps(info),self._session.id,self._stream_id,0)
        self._session.write(frame)
        self.emit("close",self)
        logging.debug("session %s stream %s close",self._session.id,self._stream_id)

    def ctl_close(self,info):
        self._session.close_stream(self)
        self.emit("close",self)
        logging.debug("session %s stream %s close",self._session.id,self._stream_id)

    def loop(self):
        if time.time()-self._last_recv_time>600:
            self.close()