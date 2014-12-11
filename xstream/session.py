# -*- coding: utf-8 -*-
#14-4-22
# create by: snower

from ssloop import EventEmitter
from connection import Connection
from center import Center
from stream import Stream, StreamFrame

class Session(EventEmitter):
    def __init__(self, session_id, is_server=False):
        super(Session, self).__init__()

        self._is_server = is_server
        self._session_id = session_id
        self._current_stream_id = 1 if is_server else 2
        self._connections = []
        self._streams = {}
        self._center = Center()

        self._center.on("frame", self.on_frame)

    @property
    def id(self):
        return self._session_id

    def add_connection(self, conn):
        connection = Connection(conn, self)
        self._connections.append(connection)
        self._center.add_connection(connection)

    def remove_connection(self, conn):
        for connection in self._connections:
            if connection._connection == conn:
                self._center.remove_connection(connection)
                self._connections.remove(connection)
        if not self._connections:
            self.emit("close", self)

    def on_frame(self, center, frame):
        if frame.action == 0:
            stream_frame = StreamFrame.loads(frame.data)
            if stream_frame.stream_id not in self._streams:
                self.create_stream(stream_frame.stream_id)
            self._streams[stream_frame.stream_id].on_frame(stream_frame)
        else:
            self.on_action(frame.action, frame.data)

    def get_stream_id(self):
        stream_id = self._current_stream_id
        self._current_stream_id += 1
        if self._current_stream_id > 0xffff:
            self._current_stream_id = 1 if self._is_server else 2
        return stream_id

    def create_stream(self, stream_id = None):
        if stream_id is None:
            stream_id = self.get_stream_id()
        stream = Stream(stream_id, self)
        self._streams[stream_id] = stream
        self.emit("stream", self, stream)
        return stream

    def stream(self):
        return self.create_stream()

    def close_stream(self, stream):
        if stream.id in self._streams:
            self._streams.pop(stream.id)

    def write(self, frame):
        data = frame.dumps()
        self._center.write(self._session_id, data)

    def on_action(self, action, data):
        pass

    def __str__(self):
        return "<%s %s>" % (super(Session, self).__str__(), self._session_id)