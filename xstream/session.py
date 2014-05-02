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

SYN_SESSION=0x01
SYN_CONNECTION=0x02
SYN_OK=0x03

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
    def __init__(self,ip,port):
        super(Server,self).__init__(ip,port)
        self._server=None

    def listen(self):
        self._server=ssloop.Server((self._ip,self._port))
        self._server.on("connection",self.on_connection)
        self._server.listen(1024)
        logging.info("server %s listen %s:%s",self,self._ip,self._port)
        BaseSession.loop_forever()

    def on_connection(self,server,connection):
        connection.on("data",self.on_data)

    def on_data(self,connection,data):
        type=ord(data[0])
        addr=connection.addr or ('',0)
        if type==SYN_SESSION:
            config=bson.loads(data[1:])
            session=Session(addr[0],addr[1],Session.SESSION_TYPE.SERVER,**config)
            connection.write(struct.pack("B",SYN_OK)+struct.pack("H",session.id)+bson.dumps(session._config))
            self._sessions[session.id]=session
            self.emit("session",self,session)
            logging.info("server session %s connect",session._session_id)
            return
        elif type==SYN_CONNECTION:
            session_id=struct.unpack("H",data[1:])[0]
            if session_id in self._sessions:
                session=self._sessions[session_id]
                if session._ip==addr[0]:
                    connection.remove_listener("data",self.on_data)
                    session.add_connection(connection)
                    connection.write(struct.pack("B",SYN_OK))
                    logging.info("server session %s connection %s connected",session._session_id,connection)
                    return
        connection.close()

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

    @property
    def id(self):
        return self._session_id

    def get_next_session_id(self):
        sid=self._sessions.keys()[-1]+1 if len(self._sessions)>0 else 1
        if sid>0xffff:sid=1
        while sid in self._sessions:sid+=1
        return sid

    def get_next_stream_id(self):
        sid=self._streams.keys()[-1]+1 if len(self._streams)>0 else (1 if self._type==self.SESSION_TYPE.CLIENT else 2)
        if self._type==self.SESSION_TYPE.CLIENT and sid % 2 ==0 : sid+=1
        elif self._type==self.SESSION_TYPE.SERVER and sid % 2 !=0 : sid+=1
        if sid>0xffff:sid=1 if self._type==self.SESSION_TYPE.CLIENT else 2
        while sid in self._streams: sid+=2
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
        logging.info("session %s connection %s colse",self._session_id,connection)

    def open(self):
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
        logging.info("session %s close",self._session_id)

    def on_connection(self,connection):
        connection.on("data",self.on_data)
        connection.write(struct.pack("B",SYN_SESSION)+bson.dumps(self._config))

    def on_data(self,connection,data):
        type=ord(data[0])
        if type==SYN_OK:
            self._session_id=struct.unpack("H",data[1:3])[0]
            self._status=self.STATUS.CONNECTED
            logging.info("session %s connected",self._session_id)

            self._status=self.STATUS.AUTHED
            logging.info("session %s authed",self._session_id)

            connection.remove_listener("close",self.on_close)
            connection.remove_listener("data",self.on_data)
            connection.on("close",self.on_fork_close)
            connection.on("data",self.on_fork_data)
            connection.write(struct.pack("B",SYN_CONNECTION)+struct.pack("H",self._session_id))
            self.fork_connection()

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

            logging.info("session %s connection %s connected",self._session_id,connection)

    def on_fork_close(self,connection):
        self._connectings.remove(connection)

    def connection_ready(self):
        self.emit("ready",self)
        self._status=self.STATUS.STREAMING
        if self._type==self.SESSION_TYPE.CLIENT:
            stream=StrictStream(self,0)
            self._control=SessionControl(self,stream)
            self._streams[0]=stream
            stream.open()
        logging.info("session %s ready",self._session_id)

    def streaming(self):
        self.emit("streaming",self)
        self.loop.timeout(2,self.session_loop)
        logging.info("session %s streaming",self._session_id)

    def session_loop(self):
        if self._status==self.STATUS.STREAMING:
            try:
                for connection in self._connections:
                    connection.loop()
                for stream_id,stream in self._streams.items():
                    stream.loop()
                self.check()
            except Exception,e:
                logging.error("session %s loop error:%s",self._session_id,e)
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
            logging.info("session %s close",self._session_id)

    def stream(self,strict=False):
        sid=self.get_next_stream_id()
        stream=StrictStream(self,sid) if strict else Stream(self,sid)
        self._streams[sid]=stream
        self.emit("stream",self,stream)
        logging.debug("session %s stream %s open",self._session_id,stream._stream_id)
        return stream

    def close_stream(self,stream):
        if stream.id in self._streams:
            del self._streams[stream.id]

    def stream_fault(self,connection,frame):
        if frame.stream_id==0:
            if not self._control:
                stream=StrictStream(self,0)
                self._control=SessionControl(self,stream)
                self._streams[0]=stream
        else:
            if frame.frame_id==0:
                stream=StrictStream(self,frame.stream_id)
                self._streams[frame.stream_id]=stream
                self.emit("stream",self,stream)
                logging.debug("session %s stream %s open",self._session_id,stream._stream_id)
            elif frame.frame_id==1:
                stream=Stream(self,frame.stream_id)
                self._streams[frame.stream_id]=stream
                self.emit("stream",self,stream)
                logging.debug("session %s stream %s open",self._session_id,stream._stream_id)

    def on_frame(self,connection,frame):
        if frame.session_id==self._session_id:
            if frame.stream_id not in self._streams:
                self.stream_fault(connection,frame)
            if frame.stream_id in self._streams:
                self._streams[frame.stream_id].on_frame(frame)

    def write(self,frame):
        if self._status==self.STATUS.STREAMING and frame.session_id==self._session_id and frame.stream_id in self._streams:
            connection=random.choice(self._connections)
            connection.write(frame)
