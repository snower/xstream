# -*- coding: utf-8 -*-
#14-4-24
# create by: snower

import struct
import time
import logging
from ssloop import EventEmitter
from frame import Frame

class Connection(EventEmitter):
    class STATUS:
        UNINIT=0
        CONNECTED=1

    def __init__(self,connection):
        super(Connection,self).__init__()
        self._connection=connection
        self._connection.on("data",self.on_data)
        self._connection.on("close",self.on_close)
        self._buffer=''
        self.status=self.STATUS.UNINIT
        self._time=time.time()
        self._ping_time=0

    def on_data(self, connection, data):
        self._buffer+=data
        while self.read():pass
        self._time=time.time()

    def read(self):
        if len(self._buffer)<2:return False
        flen=struct.unpack('H',self._buffer[:2])[0]
        if len(self._buffer)>=flen+2:
            frame=Frame(self._buffer[2:flen+2])
            if frame.session_id==0 and frame.stream_id==0 and frame.frame_id==0 and frame.data=="ping":
                self.ping()
            else:
                self.emit("frame",self,frame)
            self._buffer=self._buffer[flen+2:]
            return True
        return False

    def on_close(self,s):
        self.emit("close",self)

    def write(self,frame):
        data=str(frame)
        self._connection.write(struct.pack('H',len(data))+data)
        self._time=time.time()

    def close(self):
        self._connection.close()

    def ping(self):
        if self._ping_time==0:
            frame=Frame("ping",0,0,0)
            self.write(frame)
        self._ping_time=0
        logging.debug("connection %s ping",self)

    def loop(self):
        if self._ping_time!=0 and time.time()-self._ping_time>=30:
            pass
        elif time.time()-self._time>=30:
            frame=Frame("ping",0,0,0)
            self._ping_time=time.time()
            self.write(frame)
