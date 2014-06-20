# -*- coding: utf-8 -*-
#14-4-24
# create by: snower

import struct
import time
import random
import logging
from ssloop import EventEmitter
from frame import Frame

SYN_PING=0x01
SYN_CLOSING=0x02

class Connection(EventEmitter):
    def __init__(self,connection,crypto):
        super(Connection,self).__init__()
        self._connection=connection
        self._crypto=crypto
        self._connection.on("data",self.on_data)
        self._connection.on("close",self.on_close)
        self._buffer=''
        self._expired_time=time.time()+random.randint(180,600)
        self._time=time.time()
        self._ping_time=0
        self._closing=False

    @property
    def addr(self):
        return self._connection.addr

    def on_data(self, connection, data):
        self._buffer+=self._crypto.decrypt(data)
        while self.read():pass
        self._time=time.time()

    def on_close(self,s):
        self.emit("close",self)
        self._connection=None

    def read(self):
        if len(self._buffer)<2:return False
        flen=struct.unpack('!H',self._buffer[:2])[0]
        if len(self._buffer)>=flen+6:
            if self._buffer[flen+2:flen+6]!='\x00\xff\x00\xff':
                logging.error("stream connection %s  verify error",self)
                self.close()
                return False
            frame=Frame(self._buffer[2:flen+2])
            if frame.session_id==0 and frame.stream_id==0 and frame.frame_id==0:
                self.control(frame)
            else:
                self.emit("frame",self,frame)
            self._buffer=self._buffer[flen+6:]
            return True
        return False

    def write(self,frame,force=False):
        if self._closing:return False
        if not force and len(self._connection._buffers)>0:return False
        data=str(frame)
        self._time=time.time()
        data="".join([struct.pack('!H',len(data)),data,'\x00\xff\x00\xff'])
        return self._connection.write(self._crypto.encrypt(data))

    def close(self):
        self._closing=True
        if self._connection:
            self._connection.end()

    def __del__(self):
        self.close()

    def control(self,frame):
        type=ord(frame.data[0])
        if type==SYN_PING:
            self.ping()
        elif type==SYN_CLOSING:
            self.close()

    def write_control(self,type,data=""):
        data=struct.pack("!B",type)+data
        frame=Frame(data,0,0,0)
        self.write(frame,True)

    def ping(self):
        if self._ping_time==0:
            self.write_control(SYN_PING)
        self._ping_time=0
        logging.debug("xstream connection %s ping",self)

    def loop(self,expired=True):
        if self._closing:return
        if expired and len(self._connection._buffers)==0 and time.time()>self._expired_time:
            self.write_control(SYN_CLOSING)
            self._closing=True
        elif self._ping_time!=0 and time.time()-self._ping_time>=30:
            self._connection.close()
            logging.error("xstream connection %s ping timeout close",self)
        elif time.time()-self._time>=30:
            self.write_control(SYN_PING)
            self._ping_time=time.time()
