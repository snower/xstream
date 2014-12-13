# -*- coding: utf-8 -*-
# 14/12/10
# create by: snower

import time
import struct
from collections import deque
import bisect
from ssloop import EventEmitter, current
from frame import Frame

ACTION_ACK = 0x01
ACTION_RESEND = 0x02
ACTION_INDEX_RESET = 0x03
ACTION_INDEX_RESET_ACK = 0x04

class Center(EventEmitter):
    def __init__(self, session):
        super(Center, self).__init__()

        self.session = session
        self.frames = deque()
        self.recv_frames = []
        self.recv_index = 1
        self.send_frames = []
        self.send_index = 1
        self.drain_connections = deque()
        self.ack_time = 0
        self.ack_timeout_loop = False
        self.ttls = deque()
        self.wait_reset_frames = None

    def add_connection(self, connection):
        connection.on("frame", self.on_frame)
        connection.on("drain", self.on_drain)
        self.drain_connections.append(connection)

    def remove_connection(self, connection):
        if connection in self.drain_connections:
            self.drain_connections.remove(connection)

    def create_frame(self, data, action=0, flag=0):
        if self.send_index >= 0xffffffff:
            self.write_action(ACTION_INDEX_RESET)
            self.wait_reset_frames = deque()
            self.send_index = 1
        frame = Frame(1, self.session.id, flag, self.send_index, None, action, data)
        self.send_index += 1
        return frame

    def write(self, data):
        frame = self.create_frame(data)
        if self.wait_reset_frames is None:
            self.frames.append(frame)
            self.write_frame()
        else:
            self.wait_reset_frames.append(frame)

    def write_frame(self):
        while self.drain_connections:
            connection = self.drain_connections.popleft()
            if not connection._closed:
                return self.write_next(connection)

    def write_next(self, connection):
        frame = self.frames.popleft()
        connection.write(frame.dumps())
        bisect.insort(self.send_frames, frame)

    def on_frame(self, connection, data):
        frame = Frame.loads(data)

        if frame.index < self.recv_index:
            return

        if len(self.ttls) >= 5:
            self.ttls.popleft()
        self.ttls.append(frame.ttl())

        if frame.index != self.recv_index:
            bisect.insort(self.recv_frames, frame)
        else:
            now_ts = time.time()
            while frame and frame.index == self.recv_index:
                if self.recv_frames and frame == self.recv_frames[0]:
                    frame = self.recv_frames.pop(0)
                self.emit("frame", self, frame)
                self.recv_index += 1
                frame = self.recv_frames[0] if self.recv_frames else None

                if now_ts - self.ack_time > 2:
                    current().sync(self.write_ack)
                    self.ack_time = now_ts

        if self.recv_frames and not self.ack_timeout_loop:
            ttl = max(sum(self.ttls) / len(self.ttls), 50)
            current().timeout((ttl * 1.5) / 1000, self.on_ack_timeout_loop, self.recv_index)
            self.ack_timeout_loop = True

    def on_drain(self, connection):
        if self.frames:
            self.write_next(connection)
        else:
            self.drain_connections.append(connection)

    def on_action(self, action, data):
        if action == ACTION_ACK:
            index = struct.unpack("!I", data)
            while self.send_frames and self.send_frames[0].index <= index:
                self.send_frames.pop(0)
        elif action == ACTION_RESEND:
            index = struct.unpack("!I", data)
            while self.send_frames and self.send_frames[0].index <= index:
                frame = self.send_frames.pop(0)
                if self.send_frames[0].index == index:
                    self.frames.appendleft(frame)
                    return self.write_frame()
        elif action == ACTION_INDEX_RESET:
            self.write_action(ACTION_INDEX_RESET)
            self.recv_index = 0
        elif action == ACTION_INDEX_RESET_ACK:
            self.send_frames = []
            self.frames.extend(self.wait_reset_frames)
            self.wait_reset_frames = None
            if self.frames:
                self.write_frame()

    def write_action(self, action, data):
        frame = self.create_frame(data, action = action)
        if self.wait_reset_frames is None:
            self.frames.append(frame)
            self.write_frame()
        else:
            self.wait_reset_frames.append(frame)

    def write_ack(self):
        data = struct.pack("!I", self.recv_index - 1)
        self.write_action(ACTION_ACK, data)

    def on_ack_timeout_loop(self, recv_index):
        if recv_index == self.recv_index:
            data = struct.pack("!I", recv_index)
            self.write_action(ACTION_RESEND, data)
        if self.recv_frames:
            ttl = max(sum(self.ttls) / len(self.ttls), 50)
            current().timeout((ttl * 1.5) / 1000, self.on_ack_timeout_loop, self.recv_index)
        else:
            self.ack_timeout_loop = False
