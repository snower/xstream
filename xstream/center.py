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
        self.send_frames = {}
        self.send_index = 1
        self.drain_connections = deque()
        self.ack_time = 0
        self.ack_timeout_loop = False
        self.ttls = deque()

    def add_connection(self, connection):
        connection.on("frame", self.on_frame)
        connection.on("drain", self.on_drain)
        self.drain_connections.append(connection)

    def remove_connection(self, connection):
        if connection in self.drain_connections:
            self.drain_connections.remove(connection)

    def write(self, data):
        frame = Frame(1, self.session.id, 0, self.send_index, None, 0, data)
        self.send_index += 1
        self.frames.append(frame)
        self.write_frame()

    def write_frame(self):
        if self.drain_connections:
            connection = self.drain_connections.popleft()
            self.write_next(connection)

    def write_next(self, connection):
        frame = self.frames.popleft()
        connection.write(frame.dumps())
        self.send_frames[frame.index] = frame

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
            ttl = sum(self.ttls)
            current().timeout(ttl * 1.5, self.on_ack_timeout_loop, self.recv_index)

    def on_drain(self, connection):
        if self.frames:
            self.write_next(connection)
        else:
            self.drain_connections.append(connection)

    def on_action(self, action, data):
        if action == ACTION_ACK:
            index = struct.unpack("!Q", data)
            send_indexs = sorted(self.send_frames.keys())
            for send_index in send_indexs:
                if send_index > index:
                    break
                self.send_frames.pop(send_index)
        elif action == ACTION_RESEND:
            index = struct.unpack("!Q", data)
            send_indexs = sorted(self.send_frames.keys())
            for send_index in send_indexs:
                if send_index > index:
                    break
                if send_index == index:
                    self.frames.appendleft(self.send_frames[send_index])
                    self.write_frame()
                    break
                self.send_frames.pop(send_index)

    def write_action(self, action, data):
        frame = Frame(1, self.session.id, 0, self.send_index, None, action, data)
        self.send_index += 1
        self.frames.append(frame)
        self.write_frame()

    def write_ack(self):
        data = struct.pack("!Q", self.recv_index - 1)
        self.write_action(ACTION_ACK, data)

    def on_ack_timeout_loop(self, recv_index):
        if recv_index == self.recv_index:
            data = struct.pack("!Q", recv_index)
            self.write_action(ACTION_RESEND, data)
        if self.recv_frames:
            ttl = sum(self.ttls)
            current().timeout(ttl * 1.5, self.on_ack_timeout_loop, self.recv_index)