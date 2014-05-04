# -*- coding: utf-8 -*-
#14-4-24
# create by: snower

import struct
import time
import logging
from ssloop import EventEmitter
from frame import Frame

SYN_PING=0x01

class Connection(EventEmitter):
    def __init__(self,connection):
        super(Connection,self).__init__()
        self._connection=connection
        self._connection.on("data",self.on_data)
        self._connection.on("close",self.on_close)
        self._buffer=''
        self._time=time.time()
        self._ping_time=0

    @property
    def addr(self):
        return self._connection.addr

    def on_data(self, connection, data):
        self._buffer+=data
        while self.read():pass
        self._time=time.time()

    def on_close(self,s):
        self.emit("close",self)

    def read(self):
        if len(self._buffer)<2:return False
        flen=struct.unpack('H',self._buffer[:2])[0]
        if len(self._buffer)>=flen+2:
            frame=Frame(self._buffer[2:flen+2])
            if frame.session_id==0 and frame.stream_id==0 and frame.frame_id==0:
                self.control(frame)
            else:
                self.emit("frame",self,frame)
            self._buffer=self._buffer[flen+2:]
            return True
        return False

    def write(self,frame):
        data=str(frame)
        self._connection.write("".join([struct.pack('H',len(data)),data]))
        self._time=time.time()

    def close(self):
        self._connection.close()

    def control(self,frame):
        type=ord(frame.data[0])
        if type==SYN_PING:
            self.ping()

    def write_control(self,type,data=""):
        data=struct.pack("B",type)+data
        frame=Frame(data,0,0,0)
        self.write(frame)

    def ping(self):
        if self._ping_time==0:
            self.write_control(SYN_PING)
        self._ping_time=0
        logging.debug("xstream connection %s ping",self)

    def loop(self):
        if self._ping_time!=0 and time.time()-self._ping_time>=30:
            self._connection.close()
            logging.error("xstream connection %s ping timeout close",self)
        elif time.time()-self._time>=30:
            self.write_control(SYN_PING)
            self._ping_time=time.time()
