# -*- coding: utf-8 -*-
#14-4-22
# create by: snower

import math
import random
import logging
import time
import bson
import struct
import ssloop
from ssloop import EventEmitter
from connection import Connection
from stream import Stream,StrictStream
from control import SessionControl
from crypto import Crypto,rand_string
import error

SYN_SESSION=0x01
SYN_AUTH=0x02
SYN_CONFIG=0x03
SYN_CONNECTION=0x04
SYN_OK=0x05
SYN_ERROR=0x06

class BaseSession(EventEmitter):
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
    _sessions={}
    def __init__(self,ip,port,crypto_alg='aes_256_cfb',crypto_key='123456789',**kwargs):
        super(Server,self).__init__(ip,port)
        self._server=None
        self._crypto_alg=crypto_alg
        self._crypto_key=crypto_key
        self._config=kwargs
        self._opening_sessions={}

    def get_next_session_id(self):
        sid=sorted(self._sessions.keys())[-1]+1 if self._sessions else 1
        if sid>0xffff:sid=1
        while sid in self._sessions:sid+=1
        return sid

    def on_session_close(self, session):
        if session.id in self._sessions:
            del self._sessions[session.id]

    def on_session_ready(self, session):
        self.emit("session",self,session)
        for id,s in self._opening_sessions.items():
            if s == session:
                del self._opening_sessions[id]
        logging.info("xstream server session %s open",session._session_id)

    def write_error(self,connection,error):
        connection.write(struct.pack("!B",SYN_ERROR)+struct.pack("!I",error[0])+error[1])
        connection.end()
        logging.error("xstream server error:%s,%s",*error)

    def listen(self,blocklog=1024):
        self._server=ssloop.Server((self._ip,self._port))
        self._server.on("connection",self.on_connection)
        self._server.listen(self._config.get("blocklog",blocklog))
        logging.info("xstream server %s listen %s:%s",self,self._ip,self._port)
        BaseSession.loop_forever()

    def on_connection(self,server,connection):
        connection.on("data", self.on_data)
        connection.on("close", self.on_close)

    def on_close(self,connection):
        if id(connection) in self._opening_sessions:
            if self._opening_sessions[id(connection)].id in self._sessions:
                del self._sessions[self._opening_sessions[id(connection)].id]
            del self._opening_sessions[id(connection)]

    def on_session(self,connection,data):
        addr=connection.addr or ('',0)
        if len(self._sessions)>self._config.get("max_session",50):
            return self.write_error(connection,error.SS_OUT_MAX_SESSION_ERROR)

        session=Session(addr[0],addr[1], self.get_next_session_id(),self._crypto_alg,self._crypto_key)
        session.on('close', self.on_session_close)
        session.on('ready', self.on_session_ready)
        connection.write(struct.pack("!BH",SYN_OK,session.id)+session._token)
        self._sessions[session.id]=session
        self._opening_sessions[id(connection)]=session
        logging.info("xstream server session %s connect",session._session_id)

    def on_auth(self,connection,data):
        session_id=struct.unpack('!H',data[:2])[0]
        if session_id not in self._sessions:
            return self.write_error(connection,error.SS_NOT_OPEND_ERROR)
        data,session=data[2:],self._sessions[session_id]

        crypto=Crypto(self._crypto_key,self._crypto_alg)
        crypto.init_decrypt(data[:64])
        token_secret=crypto.decrypt(data[64:])
        if token_secret[:16]!=session._token:
            return self.write_error(connection,error.SS_AUTH_FAIL_ERROR)
        session._ensecret=rand_string(64)
        session._desecret=token_secret[80:]
        crypto.init_encrypt(token_secret[16:80])
        connection.write(struct.pack("!B",SYN_OK)+crypto.encrypt(session._ensecret))
        session._status=Session.STATUS.AUTHED
        logging.info("xstream server session %s auth",session._session_id)

    def on_config(self,connection,data):
        session_id=struct.unpack('!H',data[:2])[0]
        if session_id not in self._sessions:
            return self.write_error(connection,error.SS_NOT_OPEND_ERROR)
        data,session=data[2:],self._sessions[session_id]

        crypto=session.get_crypto()
        config=bson.loads(crypto.decrypt(data))
        session._config.update(config)
        connection.write(struct.pack("!B",SYN_OK)+crypto.encrypt(bson.dumps(session._config)))
        session._status=Session.STATUS.CONFIGED
        logging.info("xstream server session %s config",session._session_id)

    def on_fork_connection(self,connection,data):
        session_id=struct.unpack('!H',data[:2])[0]
        if session_id not in self._sessions:
            return self.write_error(connection,error.SS_NOT_OPEND_ERROR)
        data,session=data[2:],self._sessions[session_id]

        addr=connection.addr or ('',0)
        if session._ip!=addr[0]:
            return self.write_error(connection,error.SS_FORK_ADDR_ERROR)
        if len(session._connections)>max(session._config.get("connect_count",20),20):
            return self.write_error(connection,error.SS_OUT_MAX_CONNECT_ERROR)
        session_crypto=session.get_crypto()
        data=session_crypto.decrypt(data)
        if data[:16]!=session._token:
            return self.write_error(connection,error.SS_AUTH_FAIL_ERROR)

        crypto=Crypto(self._crypto_key,self._crypto_alg)
        secret=crypto.init_encrypt()
        crypto.init_decrypt(data[16:])
        session.add_connection(connection,crypto)
        connection.write(struct.pack("!B",SYN_OK)+session_crypto.encrypt(secret))

        connection.remove_listener("data",self.on_data)
        connection.remove_listener("close",self.on_data)
        logging.info("xstream server session %s connection %s connected",session._session_id,connection)

    def on_data(self,connection,data):
        type=ord(data[0])
        if type==SYN_SESSION:
            self.on_session(connection,data[1:])
        elif type==SYN_AUTH:
            self.on_auth(connection,data[1:])
        elif type==SYN_CONFIG:
            self.on_config(connection,data[1:])
        elif type==SYN_CONNECTION:
            self.on_fork_connection(connection,data[1:])


class Session(BaseSession):
    class SESSION_TYPE:
        CLIENT=0
        SERVER=1

    class STATUS:
        INITED=0,
        CONNECTING=1
        CONNECTED=2
        AUTHED=3
        CONFIGED=4
        SLEEPING=5
        STREAMING=6
        CLOSING=7
        CLOSED=8

    def __init__(self,ip,port,sid=0,crypto_alg='aes_256_cfb',crypto_key='123456789',**kwargs):
        super(Session,self).__init__(ip,port)
        self._type=self.SESSION_TYPE.CLIENT if sid==0 else self.SESSION_TYPE.SERVER
        self._crypto_alg=crypto_alg
        self._crypto_key=crypto_key
        self._token=rand_string(16)
        self._ensecret=''
        self._desecret=''
        self._session_id=sid
        self._streams={}
        self._connections={}
        self._connections_list=[]
        self._connectings={}
        self._status=self.STATUS.CONNECTED if self._type==self.SESSION_TYPE.SERVER else self.STATUS.INITED
        self._config=kwargs
        self._control=None
        self._stream_current_id=1 if type==self.SESSION_TYPE.CLIENT else 2
        self._stream_time=time.time()
        self._connection_count=1
        self._wbuffers=[]

    @property
    def id(self):
        return self._session_id

    def get_next_stream_id(self):
        if self._stream_current_id>0xffff:
            self._stream_current_id=1 if self._type==self.SESSION_TYPE.CLIENT else 2
        while self._stream_current_id in self._streams:
            self._stream_current_id+=2
        sid=self._stream_current_id
        self._stream_current_id+=2
        return sid

    def get_crypto(self):
        crypto=Crypto(self._crypto_key,self._crypto_alg)
        crypto.init_encrypt(self._ensecret)
        crypto.init_decrypt(self._desecret)
        return crypto

    def add_connection(self,connection,crypto):
        connection=Connection(connection,crypto)
        connection.on("frame",self.on_frame)
        connection.on("close",self.on_connection_close)
        self._connections[id(connection)]=connection
        self._connections_list=self._connections.values()

        if self._status==self.STATUS.CONFIGED and len(self._connections)>=self._connection_count:
            self.connection_ready()

    def on_connection_close(self,connection):
        if id(connection) in self._connections:
            del self._connections[id(connection)]
            self._connections_list=self._connections.values()
        if self._type == self.SESSION_TYPE.SERVER and not self._connections:
            self.close()
        logging.info("xstream session %s connection %s colse %s",self._session_id,connection,len(self._connections))

    def open(self):
        if self._status!=self.STATUS.INITED:return
        connection=ssloop.Socket(self.loop)
        connection.once("connect",self.on_connection)
        connection.once("close",self.on_close)
        self._connectings[id(connection)]=(connection,)
        self._status=self.STATUS.CONNECTING
        connection.connect((self._ip,self._port))
        BaseSession.loop_forever()

    def close(self):
        if self._status==self.STATUS.CLOSED:return
        for stram_id in self._streams.keys():
            self._streams[stram_id].close()
        self._status=self.STATUS.CLOSED
        for id,connection in self._connections.items():
            connection.close()
        for id,connection in self._connectings.items():
            connection[0].close()
        self.emit("close",self)
        self.remove_all_listeners()
        logging.info("xstream session %s close",self._session_id)

    def __del__(self):
        self.close()

    def on_connection(self,connection):
        connection.on("data",self.on_data)
        connection.write(struct.pack("!B",SYN_SESSION))

    def on_session_ok(self,connection,data):
        self._session_id=struct.unpack("!H",data[:2])[0]
        self._token=data[2:]
        self._status=self.STATUS.CONNECTED
        self._ensecret=rand_string(64)
        self._desecret=rand_string(64)
        crypto=Crypto(self._crypto_key,self._crypto_alg)
        secret=crypto.init_encrypt()
        token_secret=crypto.encrypt(self._token+self._desecret+self._ensecret)
        connection.write(struct.pack("!BH",SYN_AUTH,self._session_id)+secret+token_secret)
        logging.info("xstream session %s connected",self._session_id)

    def on_auth_ok(self,connection,data):
        crypto=self.get_crypto()
        self._desecret=crypto.decrypt(data)
        self._status=self.STATUS.AUTHED
        connection.write(struct.pack("!BH",SYN_CONFIG,self._session_id)+crypto.encrypt(bson.dumps(self._config)))
        logging.info("xstream session %s auth",self._session_id)

    def on_config_ok(self,connection,data):
        crypto=self.get_crypto()
        self._config.update(bson.loads(crypto.decrypt(data)))
        self._status=self.STATUS.CONFIGED
        logging.info("xstream session %s config",self._session_id)

        connection.remove_listener("close",self.on_close)
        connection.remove_listener("data",self.on_data)
        connection.on("close",self.on_fork_close)
        self.on_fork_connection(connection)
        self.fork_connection()

    def on_data(self,connection,data):
        type=ord(data[0])
        if type==SYN_OK:
            if self._status==self.STATUS.CONNECTING:
                self.on_session_ok(connection,data[1:])
            elif self._status==self.STATUS.CONNECTED:
                self.on_auth_ok(connection,data[1:])
            elif self._status==self.STATUS.AUTHED:
                self.on_config_ok(connection,data[1:])
        elif type==SYN_ERROR:
            self.on_error(data[1:])

    def on_close(self,connection):
        if id(connection) in self._connectings:
            del self._connectings[id(connection)]
        self.close()

    def fork_connection(self):
        for i in range(self._connection_count-len(self._connections)-len(self._connectings)):
            connection=ssloop.Socket(self.loop)
            connection.once("connect",self.on_fork_connection)
            connection.once("close",self.on_fork_close)
            self._connectings[id(connection)]=(connection,)
            connection.connect((self._ip,self._port))

    def on_fork_connection(self,connection):
        connection.on("data",self.on_fork_data)
        session_crypto=self.get_crypto()
        crypto=Crypto(self._crypto_key,self._crypto_alg)
        secret=crypto.init_encrypt()
        self._connectings[id(connection)]=(connection,crypto)
        connection.write(struct.pack("!BH",SYN_CONNECTION,self._session_id)+session_crypto.encrypt(self._token+secret))

    def on_fork_data(self,connection,data):
        type=ord(data[0])
        if type==SYN_OK:
            session_crypto=self.get_crypto()
            crypto=self._connectings[id(connection)][1]
            del self._connectings[id(connection)]
            connection.remove_listener("close",self.on_fork_close)
            connection.remove_listener("data",self.on_fork_data)
            crypto.init_decrypt(session_crypto.decrypt(data[1:]))
            self.add_connection(connection,crypto)

            logging.info("xstream session %s connection %s connected %s",self._session_id,connection,len(self._connections))
        elif type==SYN_ERROR:
            self.on_error(data[1:])

    def on_fork_close(self,connection):
        del self._connectings[id(connection)]
        if not self._connections and not self._connectings:
            self.close()

    def on_error(self,data):
        code,msg=struct.unpack("!I",data[:4])[0],data[4:]
        self.emit("error",self,code,msg)
        self.close()
        logging.error("xstream session error:%s,%s",code,msg)

    def connection_ready(self):
        self.emit("ready",self)
        self._status=self.STATUS.STREAMING
        if self._type==self.SESSION_TYPE.CLIENT:
            stream=StrictStream(self,0,0xffffffff)
            self._control=SessionControl(self,stream)
            stream.open()
        logging.info("xstream session %s ready",self._session_id)

    def streaming(self):
        self.emit("streaming",self)
        self.write_buffer_frame()
        self.loop.timeout(1,self.session_loop)
        logging.info("xstream session %s streaming",self._session_id)

    def sleep(self):
        self._status=self.STATUS.SLEEPING
        logging.info("xstream session %s sleeping",self._session_id)

    def wakeup(self):
        if self._connections:
            self._status=self.STATUS.STREAMING
        else:
            for stram_id in self._streams.keys():
                self._streams[stram_id].close()
            self._session_id=0
            self._streams={}
            self._connections={}
            self._connections_list=[]
            self._connectings={}
            self._status=self.STATUS.INITED
            self._control=None
            self._stream_current_id=1
            self._stream_time=time.time()
            self._connection_count=1
            self.open()
        logging.info("xstream session wakeup")

    def session_loop(self):
        if self._status==self.STATUS.STREAMING:
            try:
                self.write_buffer_frame()
                for stream_id,stream in self._streams.items():
                    stream.loop()
                for connection in self._connections_list:
                    connection.loop(len(self._connections)>1 and self._type==self.SESSION_TYPE.CLIENT)
                self._control.loop()
                self.check()
            except Exception,e:
                logging.error("xstream session %s loop error:%s",self._session_id,e)
            self.loop.timeout(0.5,self.session_loop)
        elif self._status==self.STATUS.SLEEPING and self._connections:
            for connection in self._connections_list:
                connection.loop()
            self.loop.timeout(0.5,self.session_loop)

    def check(self):
        if self._type==self.SESSION_TYPE.CLIENT:
            if len(self._streams)<=1 and time.time()-self._stream_time>self._config.get("sleep_time_out",300):
                self.sleep()
            else:
                count=int(math.sqrt(len(self._streams))*(math.sqrt(self._config.get("connect_count",20))/10+1.2))
                self._connection_count=min(self._config.get("connect_count",20),max(count,2))
                self.fork_connection()

    def stream(self,strict=False):
        if self._status==self.STATUS.SLEEPING:
            self.wakeup()
        sid=self.get_next_stream_id()
        stream=StrictStream(self,sid,self._config.get("stream_time_out",300)) if strict else Stream(self,sid,self._config.get("stream_time_out",300))
        return stream

    def open_stream(self,stream):
        if stream.id in self._streams:return False
        self._streams[stream.id]=stream
        self.emit("stream",self,stream)
        self._stream_time=time.time()
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
            if not self._control and frame.data and ord(frame.data[0])==0x01:
                stream=StrictStream(self,0,0xffffffff)
                self._control=SessionControl(self,stream)
                stream.on_frame(frame)
        else:
            if frame.frame_id==0 and frame.data and ord(frame.data[0])==0x01:
                stream=StrictStream(self,frame.stream_id,self._config.get("stream_time_out",300))
                stream.on_frame(frame)
            elif frame.frame_id>=1:
                stream=Stream(self,frame.stream_id,self._config.get("stream_time_out",300))
                stream.on_frame(frame)

    def on_frame(self,connection,frame):
        if frame.session_id==self._session_id:
            if frame.stream_id not in self._streams:
                self.stream_fault(connection,frame)
            else:
                self._streams[frame.stream_id].on_frame(frame)
            logging.debug("xstream session read:session_id=%s,stream_id=%s,frame_id=%s,connection=%s,data_len=%s",frame.session_id,frame.stream_id,frame.frame_id,id(connection),len(frame.data))

    def write_buffer_frame(self):
        if not self._wbuffers:return
        wbuffers=self._wbuffers
        self._wbuffers=[]
        for stream,frame in wbuffers:
            frame.session_id=self._session_id
            self.write(stream,frame)

    def backup_write_frame(self,stream,frame):
        if len(self._connections)<=1:return
        if self._status==self.STATUS.STREAMING and frame.session_id==self._session_id and frame.stream_id in self._streams:
            index=int(random.random()*len(self._connections_list))
            while stream.last_write_connection_id==id(self._connections_list[index]):
                index=0 if index==len(self._connections_list)-1 else index+1
            connection=self._connections_list[index]
            connection.write(frame,True)
            return connection

    def write_frame(self,stream,frame):
        if not self._connections or self._status<self.STATUS.STREAMING:
            if frame.stream_id!=0 and frame.frame_id!=0:
                self._wbuffers.append((stream,frame))
            return
        if self._status==self.STATUS.STREAMING and frame.session_id==self._session_id and frame.stream_id in self._streams:
            if stream.last_write_connection_id and stream.last_write_connection_id in self._connections:
                connection=self._connections[stream.last_write_connection_id]
            else:
                connection=random.choice(self._connections_list)
            try_count=0
            while not connection.write(frame):
                connection=random.choice(self._connections_list)
                try_count+=1
                if try_count>len(self._connections)*1.4:
                    if not connection.write(frame,True):
                        self._wbuffers.append((stream,frame))
                        return
                    break
            stream.last_write_connection_id=id(connection)
            return connection

    def write(self,stream,frame,backup=False):
        if backup:
            connection=self.backup_write_frame(stream,frame)
        else:
            connection=self.write_frame(stream,frame)
        logging.debug("xstream session write:session_id=%s,stream_id=%s,frame_id=%s,connection=%s,data_len=%s",frame.session_id,frame.stream_id,frame.frame_id,id(connection),len(frame.data))
