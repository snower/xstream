# -*- coding: utf-8 -*-
#14-4-22
# create by: snower

from ssloop import EventEmitter
from connection import Connection
from center import Center
from stream import Stream

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

    def add_connection(self, conn):
        connection = Connection(conn, self)
        self._connections.append(connection)
        self._center.add_connection(connection)

    def on_frame(self, center, frame):
        if frame.stream_id not in self._streams:
            self.create_stream(frame.stream_id)
        self._streams[frame.stream_id].on_data(frame.data)

    def get_stream_id(self):
        stream_id = self._current_stream_id
        self._current_stream_id += 1
        if self._current_stream_id > 0xffff:
            self._current_stream_id = 1 if self.is_server else 2
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

    def write(self, stream, data):
        frame_len = 16 * 1024
        for i in range(int(len(data) / frame_len) + 1):
            self._center.write(self._session_id, stream._stream_id, data[i * frame_len: (i+1) * frame_len])