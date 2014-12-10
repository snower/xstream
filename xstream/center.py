# -*- coding: utf-8 -*-
# 14/12/10
# create by: snower

import bisect
from ssloop import EventEmitter
from frame import Frame

class Center(EventEmitter):
    def __init__(self):
        super(Center, self).__init__()

        self.frames = []
        self.recv_frames = []
        self.recv_index = 1
        self.send_index = 1
        self.drain_connections = []

    def add_connection(self, connection):
        connection.on("frame", self.on_frame)
        connection.on("drain", self.on_drain)
        self.drain_connections.append(connection)

    def write(self, session_id, stream_id, data):
        frame = Frame(session_id, 0, self.send_index, stream_id, data)
        self.send_index += 1
        self.frames.append(frame)

        if self.drain_connections:
            connection = self.drain_connections.pop()
            self.write_next(connection)

    def write_next(self, connection):
        frame = self.frames.pop(0)
        connection.write(frame.dumps())

    def on_frame(self, connection, data):
        frame = Frame.loads(data)

        if frame.index != self.recv_index:
            bisect.insort(self.recv_frames, frame)
        else:
            while frame.index == self.recv_index:
                self.emit("frame", self, frame)
                self.recv_index += 1

    def on_drain(self, connection):
        if self.frames:
            self.write_next(connection)
        else:
            self.drain_connections.append(connection)