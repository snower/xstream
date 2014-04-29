# -*- coding: utf-8 -*-
#14-4-22
# create by: snower

import time
import random
import logging
import threading
import json
import ssloop
from ssloop import EventEmitter
from connection import Connection
from stream import Stream
from frame import Frame

class BaseSession(EventEmitter):
    _sessions={}
    _loop=None

    def __init__(self,ip,port):
        super(BaseSession,self).__init__()
        self._ip=ip
        self._port=port

    @staticmethod
    def loop():
        if BaseSession._loop is None:
            BaseSession._loop=ssloop.instance()
            BaseSession._loop.start()

class Server(BaseSession):
    def __init__(self,ip,port):
        super(Server,self).__init__(ip,port)
        self._ip=ip
        self._port=port
        self._server=None

    def listen(self):
        self._server=ssloop.Server((self._ip,self._port))
        self._server.on("connection",self.on_connection)
        self._server.listen(1024)
        BaseSession.loop()
        logging.info("server %s listen",self)

    def on_connection(self,server,connection):
        connection=Connection(connection)
        connection.once("frame",self.on_frame)

    def on_frame(self,connection,frame):
        if frame.stream_id==0 and frame.frame_id==0 and frame.data[:5]=="hello":
            if frame.session_id ==0:
                session=Session('',0,Session.SESSION_TYPE.SERVER,**json.loads(frame.data[5:]))
                connection.on("frame",session.on_frame)
                connection.on("close",session.on_connection_close)
                session._connections.append(connection)

                self._sessions[session.id]=session
                self.emit("session",self,session)
                session._thread.start()
                logging.info("server session %s connect",session._session_id)

                frame=Frame("hello",session.id,0,0)
                session.write(frame)
                logging.info("server session %s connection %s connected",session._session_id,connection)
            elif frame.session_id in self._sessions:
                session=self._sessions[frame.session_id]
                connection.on("frame",session.on_frame)
                connection.on("close",session.on_connection_close)
                session._connections.append(connection)

                frame=Frame("hello",session.id,0,0)
                session.write(frame)
                logging.info("server session %s connection %s connected",session._session_id,connection)
            else:
                connection.close()

class Session(BaseSession):
    class SESSION_TYPE:
        CLIENT=0
        SERVER=1

    class STATUS:
        INITING=0,
        CONNECTED=1
        CLOSED=2

    def __init__(self,ip,port,type=SESSION_TYPE.CLIENT,**kwargs):
        super(Session,self).__init__(ip,port)
        self._type=type
        self._session_id=0 if type==self.SESSION_TYPE.CLIENT else self.get_next_session_id()
        self._streams={}
        self._connections=[]
        self._status=self.STATUS.CONNECTED if self._type==self.SESSION_TYPE.SERVER else self.STATUS.INITING
        self._config=kwargs
        self._thread=threading.Thread(target=self.session_loop)

        self._thread.setDaemon(True)

    @property
    def id(self):
        return self._session_id

    def get_next_session_id(self):
        sid=self._sessions.keys()[-1]+1 if len(self._sessions)>0 else 1
        if sid>0xffff:sid=1
        while sid in self._sessions:sid+=1
        return sid

    def get_next_stream_id(self):
        sid=self._streams.keys()[-1]+2 if len(self._streams)>0 else (1 if self._type==self.SESSION_TYPE.CLIENT else 2)
        if sid>0xffff:sid=1 if self._type==self.SESSION_TYPE.CLIENT else 2
        while sid in self._streams: sid+=2
        return sid

    def session_loop(self):
        while self._status==self.STATUS.CONNECTED:
            try:
                for connection in self._connections:
                    connection.loop()
                for stream_id,stream in self._streams.items():
                    stream.loop()
                self.check()
            except Exception,e:
                logging.error("session %s loop error:%s",self._session_id,e)
            time.sleep(2)

    def open(self):
        connection=ssloop.Socket(self._loop)
        connection.once("connect",self.on_connection)
        connection.connect((self._ip,self._port))
        BaseSession.loop()

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

    def check(self):
        if self._type==self.SESSION_TYPE.CLIENT and self._status!=self.STATUS.CLOSED:
            if len(self._connections)>=self._config.get("connect_count",20) and self._status==self.STATUS.INITING:
                self._status=self.STATUS.CONNECTED
                self.emit("ready",self)
                self._thread.start()
                logging.info("session %s ready",self._session_id)
            elif len(self._connections)<self._config.get("connect_count",20):
                connection=ssloop.Socket(self._loop)
                connection.once("connect",self.on_connection)
                connection.connect((self._ip,self._port))
        if self._type==self.SESSION_TYPE.SERVER and not self._connections:
            self._status=self.STATUS.CLOSED
            for stram_id in self._streams.keys():
                self._streams[stram_id].close()
            del self._sessions[self._session_id]
            self.emit("close",self)
            logging.info("session %s close",self._session_id)

    def stream(self):
        sid=self.get_next_stream_id()
        stream=Stream(self,sid)
        self._streams[sid]=stream
        self.emit("stream",self,stream)
        logging.debug("session %s stream %s open",self._session_id,stream._stream_id)
        return stream

    def close_stream(self,stream):
        if stream.id in self._streams:
            del self._streams[stream.id]

    def on_connection(self,connection):
        frame=Frame("hello"+json.dumps(self._config),self._session_id,0,0)
        connection=Connection(connection)
        connection.on("frame",self.on_frame)
        connection.on("close",self.on_connection_close)
        connection.write(frame)

    def on_connection_close(self,connection):
        self._connections.remove(connection)
        logging.info("session %s connection %s colse",self._session_id,connection)

    def command(self,connection,frame):
        if frame.data=="hello":
            self._session_id=frame.session_id
            if connection not in self._connections:self._connections.append(connection)
            self.check()
            logging.info("session %s connection %s connected",self._session_id,connection)

    def on_frame(self,connection,frame):
        if frame.stream_id==0 and frame.frame_id==0:
            self.command(connection,frame)
        elif frame.session_id==self._session_id:
            if frame.stream_id not in self._streams:
                stream=Stream(self,frame.stream_id)
                self._streams[frame.stream_id]=stream
                self.emit("stream",self,stream)
                logging.debug("session %s stream %s open",self._session_id,stream._stream_id)
            self._streams[frame.stream_id].on_frame(frame)

    def write(self,frame):
        if self._status!=self.STATUS.CONNECTED:return False
        connection=random.choice(self._connections)
        connection.write(frame)
