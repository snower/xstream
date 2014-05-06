# -*- coding: utf-8 -*-
#14-4-22
# create by: snower

import random
import logging
import bson
import struct
import ssloop
from ssloop import EventEmitter
from connection import Connection
from stream import Stream,StrictStream
from control import SessionControl
import error

SYN_SESSION=0x01
SYN_CONNECTION=0x02
SYN_OK=0x03
SYN_ERROR=0x04

class BaseSession(EventEmitter):
    _sessions={}
    loop=None

    def __init__(self,ip,port):
        super(BaseSession,self).__init__()
        self._ip=ip
        self._port=port

    @staticmethod
    def loop_forever():
        if BaseSession.loop is None:
            BaseSession.loop=ssloop.instance()
            BaseSession.loop.start()

class Server(BaseSession):
    def __init__(self,ip,port,**kwargs):
        super(Server,self).__init__(ip,port)
        self._server=None
        self._config=kwargs

    def write_error(self,connection,error):
        connection.write(struct.pack("B",SYN_ERROR)+struct.pack("I",error[0])+error[1])
        connection.end()
        logging.error("xstream server error:%s,%s",*error)

    def listen(self,blocklog=1024):
        self._server=ssloop.Server((self._ip,self._port))
        self._server.on("connection",self.on_connection)
        self._server.listen(blocklog)
        logging.info("xstream server %s listen %s:%s",self,self._ip,self._port)
        BaseSession.loop_forever()

    def on_connection(self,server,connection):
        connection.on("data",self.on_data)

    def on_data(self,connection,data):
        type=ord(data[0])
        addr=connection.addr or ('',0)
        if type==SYN_SESSION:
            if len(self._sessions)>self._config.get("max_session",50):
                return self.write_error(connection,error.SS_OUT_MAX_SESSION_ERROR)
            config=bson.loads(data[1:])
            session=Session(addr[0],addr[1],Session.SESSION_TYPE.SERVER,**config)
            connection.write(struct.pack("B",SYN_OK)+struct.pack("H",session.id)+bson.dumps(session._config))
            self._sessions[session.id]=session
            self.emit("session",self,session)
            logging.info("xstream server session %s connect",session._session_id)
        elif type==SYN_CONNECTION:
            session_id=struct.unpack("H",data[1:])[0]
            if session_id not in self._sessions:
                return self.write_error(connection,error.SS_NOT_OPEND_ERROR)
            session=self._sessions[session_id]
            if session._ip!=addr[0]:
                return self.write_error(connection,error.SS_FORK_ADDR_ERROR)
            if len(session._connections)>max(session._config.get("connect_count",20),20):
                return self.write_error(connection,error.SS_OUT_MAX_CONNECT_ERROR)
            connection.remove_listener("data",self.on_data)
            session.add_connection(connection)
            connection.write(struct.pack("B",SYN_OK))
            logging.info("xstream server session %s connection %s connected",session._session_id,connection)

class Session(BaseSession):
    class SESSION_TYPE:
        CLIENT=0
        SERVER=1

    class STATUS:
        INITED=0,
        CONNECTING=1
        CONNECTED=2
        AUTHING=3,
        AUTHED=4,
        STREAMING=5,
        CLOSING=6,
        CLOSED=7

    def __init__(self,ip,port,type=SESSION_TYPE.CLIENT,**kwargs):
        super(Session,self).__init__(ip,port)
        self._type=type
        self._session_id=0 if type==self.SESSION_TYPE.CLIENT else self.get_next_session_id()
        self._streams={}
        self._connections=[]
        self._connectings=[]
        self._status=self.STATUS.AUTHED if self._type==self.SESSION_TYPE.SERVER else self.STATUS.INITED
        self._config=kwargs
        self._control=None
        self._stream_current_id=1 if type==self.SESSION_TYPE.CLIENT else 2

    @property
    def id(self):
        return self._session_id

    def get_next_session_id(self):
        sid=self._sessions.keys()[-1]+1 if len(self._sessions)>0 else 1
        if sid>0xffff:sid=1
        while sid in self._sessions:sid+=1
        return sid

    def get_next_stream_id(self):
        if self._stream_current_id>0xffff:
            self._stream_current_id=1 if self._type==self.SESSION_TYPE.CLIENT else 2
        while self._stream_current_id in self._streams:
            self._stream_current_id+=2
        sid=self._stream_current_id
        self._stream_current_id+=2
        return sid

    def add_connection(self,connection):
        connection=Connection(connection)
        connection.on("frame",self.on_frame)
        connection.on("close",self.on_connection_close)
        self._connections.append(connection)

        if self._status==self.STATUS.AUTHED and len(self._connections)>=self._config.get("connect_count",20):
            self.connection_ready()

    def on_connection_close(self,connection):
        if connection in self._connections:self._connections.remove(connection)
        logging.info("xstream session %s connection %s colse",self._session_id,connection)

    def open(self):
        if self._status!=self.STATUS.INITED:return
        connection=ssloop.Socket(self.loop)
        connection.once("connect",self.on_connection)
        connection.once("close",self.on_close)
        self._connectings.append(connection)
        self._status=self.STATUS.CONNECTING
        connection.connect((self._ip,self._port))
        BaseSession.loop_forever()

    def close(self):
        if self._status==self.STATUS.CLOSED:return
        for stram_id in self._streams.keys():
            self._streams[stram_id].close()
        self._status=self.STATUS.CLOSED
        for connection in self._connections:
            connection.close()
        self.emit("close",self)
        del self._sessions[self._session_id]
        logging.info("xstream session %s close",self._session_id)

    def on_connection(self,connection):
        connection.on("data",self.on_data)
        connection.write(struct.pack("B",SYN_SESSION)+bson.dumps(self._config))

    def on_data(self,connection,data):
        type=ord(data[0])
        if type==SYN_OK:
            self._session_id=struct.unpack("H",data[1:3])[0]
            self._status=self.STATUS.CONNECTED
            logging.info("xstream session %s connected",self._session_id)

            self._status=self.STATUS.AUTHED
            logging.info("xstream session %s authed",self._session_id)

            connection.remove_listener("close",self.on_close)
            connection.remove_listener("data",self.on_data)
            connection.on("close",self.on_fork_close)
            connection.on("data",self.on_fork_data)
            connection.write(struct.pack("B",SYN_CONNECTION)+struct.pack("H",self._session_id))
            self.fork_connection()
        elif type==SYN_ERROR:
            self.on_error(data[1:])

    def on_close(self,connection):
        self._connectings.remove(connection)
        self.emit("close",self)

    def fork_connection(self):
        for i in range(self._config.get("connect_count",20)-len(self._connections)-len(self._connectings)):
            connection=ssloop.Socket(self.loop)
            connection.once("connect",self.on_fork_connection)
            connection.once("close",self.on_fork_close)
            self._connectings.append(connection)
            connection.connect((self._ip,self._port))

    def on_fork_connection(self,connection):
        connection.on("data",self.on_fork_data)
        connection.write(struct.pack("B",SYN_CONNECTION)+struct.pack("H",self._session_id))

    def on_fork_data(self,connection,data):
        type=ord(data[0])
        if type==SYN_OK:
            self._connectings.remove(connection)
            connection.remove_listener("close",self.on_fork_close)
            connection.remove_listener("data",self.on_fork_data)
            self.add_connection(connection)

            logging.info("xstream session %s connection %s connected",self._session_id,connection)
        elif type==SYN_ERROR:
            self.on_error(data[1:])

    def on_fork_close(self,connection):
        self._connectings.remove(connection)

    def on_error(self,data):
        code,msg=struct.unpack("I",data[:4])[0],data[4:]
        self.emit("error",self,code,msg)
        logging.error("xstream session error:%s,%s",code,msg)

    def connection_ready(self):
        self.emit("ready",self)
        self._status=self.STATUS.STREAMING
        if self._type==self.SESSION_TYPE.CLIENT:
            stream=StrictStream(self,0)
            self._control=SessionControl(self,stream)
            stream.open()
        logging.info("xstream session %s ready",self._session_id)

    def streaming(self):
        self.emit("streaming",self)
        self.loop.timeout(2,self.session_loop)
        logging.info("xstream session %s streaming",self._session_id)

    def session_loop(self):
        if self._status==self.STATUS.STREAMING:
            try:
                for connection in self._connections:
                    connection.loop()
                for stream_id,stream in self._streams.items():
                    stream.loop()
                self.check()
            except Exception,e:
                logging.error("xstream session %s loop error:%s",self._session_id,e)
            self.loop.timeout(2,self.session_loop)

    def check(self):
        if self._type==self.SESSION_TYPE.CLIENT and self._status!=self.STATUS.CLOSED:
            self.fork_connection()
        if self._type==self.SESSION_TYPE.SERVER and not self._connections:
            self._status=self.STATUS.CLOSED
            for stram_id in self._streams.keys():
                self._streams[stram_id].close()
            del self._sessions[self._session_id]
            self.emit("close",self)
            logging.info("xstream session %s close",self._session_id)

    def stream(self,strict=False):
        sid=self.get_next_stream_id()
        stream=StrictStream(self,sid) if strict else Stream(self,sid)
        return stream

    def open_stream(self,stream):
        if stream.id in self._streams:return False
        self._streams[stream.id]=stream
        self.emit("stream",self,stream)
        logging.debug("xstream session %s stream %s open",self._session_id,stream._stream_id)
        return True

    def close_stream(self,stream):
        if stream.id in self._streams:
            del self._streams[stream.id]
            logging.debug("xstream session %s stream %s close",self._session_id,stream._stream_id)
            return True
        return False

    def stream_fault(self,connection,frame):
        if frame.stream_id==0:
            if not self._control:
                stream=StrictStream(self,0)
                self._control=SessionControl(self,stream)
                stream.on_frame(frame)
        else:
            if frame.frame_id==0:
                stream=StrictStream(self,frame.stream_id)
                stream.on_frame(frame)
            elif frame.frame_id==1:
                stream=Stream(self,frame.stream_id)
                stream.on_frame(frame)

    def on_frame(self,connection,frame):
        if frame.session_id==self._session_id:
            if frame.stream_id not in self._streams:
                self.stream_fault(connection,frame)
            else:
                self._streams[frame.stream_id].on_frame(frame)
            logging.debug("xstream session read:session_id=%s,stream_id=%s,frame_id=%s,connection=%s,data_len=%s",frame.session_id,frame.stream_id,frame.frame_id,id(connection),len(frame.data))


    def write(self,frame):
        if self._status==self.STATUS.STREAMING and frame.session_id==self._session_id and frame.stream_id in self._streams:
            connection=random.choice(self._connections)
            try_count=0
            while not connection.write(frame):
                connection=random.choice(self._connections)
                try_count+=1
                if try_count>len(self._connections)*100:
                    connection.write(frame,True)
                    break
            logging.debug("xstream session write:session_id=%s,stream_id=%s,frame_id=%s,connection=%s,data_len=%s",frame.session_id,frame.stream_id,frame.frame_id,id(connection),len(frame.data))
