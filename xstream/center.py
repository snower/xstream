# -*- coding: utf-8 -*-
# 14/12/10
# create by: snower

import time
import logging
import struct
from collections import deque
import bisect
from sevent import EventEmitter, current
from frame import Frame

ACTION_ACK = 0x01
ACTION_RESEND = 0x02
ACTION_INDEX_RESET = 0x03
ACTION_INDEX_RESET_ACK = 0x04
ACTION_TTL = 0x05
ACTION_TTL_ACK = 0x06

class Center(EventEmitter):
    def __init__(self, session):
        super(Center, self).__init__()

        self.session = session
        self.frames = []
        self.recv_frames = []
        self.recv_index = 1
        self.send_frames = []
        self.send_index = 1
        self.drain_connections = deque()
        self.ack_time = 0
        self.ack_timeout_loop = False
        self.ttls = [0]
        self.ttl = 1000
        self.wait_reset_frames = None
        self.closed = False

        self.write_ttl()

    def add_connection(self, connection):
        connection.on("frame", self.on_frame)
        connection.on("drain", self.on_drain)
        if self.frames:
            self.write_next(connection)
        else:
            self.drain_connections.append(connection)

    def remove_connection(self, connection):
        if connection in self.drain_connections:
            self.drain_connections.remove(connection)

    def create_frame(self, data, action=0, flag=0, index=None):
        if index is None:
            if self.send_index >= 0xffffffff:
                self.write_action(ACTION_INDEX_RESET, index=self.send_index)
                self.wait_reset_frames = []
                self.send_index = 1
            frame = Frame(1, self.session.id, flag, self.send_index, None, action, data)
            self.send_index += 1
        else:
            frame = Frame(1, self.session.id, flag, index, None, action, data)
        return frame

    def write(self, data):
        frame = self.create_frame(data)
        if self.wait_reset_frames is None:
            bisect.insort(self.frames, frame)
            self.write_frame()
        else:
            bisect.insort(self.wait_reset_frames, frame)

    def write_frame(self):
        for _ in range(len(self.drain_connections)):
            connection = self.drain_connections.pop()
            if not connection._closed:
                if self.write_next(connection):
                    return

    def write_next(self, connection):
        frame = self.frames.pop(0)
        if connection == frame.connection:
            frames = []
            while frame and connection == frame.connection:
                bisect.insort(frames, frame)
                frame = self.frames.pop(0) if self.frames else None
            if frames:
                self.frames = frames + self.frames

        if frame:
            connection.write(frame.dumps())
            if frame.index != 0:
                frame.connection = connection
                bisect.insort(self.send_frames, frame)
            
        else:
            self.drain_connections.appendleft(connection)
        return frame

    def on_frame(self, connection, data):
        frame = Frame.loads(data, connection)

        if frame.index == 0:
            return self.emit("frame", self, frame)

        if frame.index < self.recv_index or abs(frame.index - self.recv_index) > 0x7fffffff:
            return

        if frame.index == self.recv_index:
            while frame and frame.index <= self.recv_index:
                if frame.index == self.recv_index:
                    self.emit("frame", self, frame)
                    self.recv_index += 1

                frame = self.recv_frames.pop(0) if self.recv_frames else None

            now_ts = time.time()
            if now_ts - self.ack_time > 2:
                current().sync(self.write_ack)
                self.ack_time = now_ts

        if frame:
            bisect.insort_left(self.recv_frames, frame)

        if self.recv_frames and not self.ack_timeout_loop:
            current().timeout(self.ttl * 0.7 / 1000, self.on_ack_timeout_loop, self.recv_index)
            self.ack_timeout_loop = True

    def on_drain(self, connection):
        if self.frames:
            self.write_next(connection)
        else:
            self.drain_connections.append(connection)

    def on_action(self, action, data):
        if action == ACTION_ACK:
            index, = struct.unpack("!I", data)
            while self.send_frames and self.send_frames[0].index <= index:
                self.send_frames.pop(0)
        elif action == ACTION_RESEND:
            index, recv_index = struct.unpack("!II", data)
            recv_index = index + int((recv_index - index) * 0.8)
            while self.send_frames and self.send_frames[0].index <= recv_index:
                frame = self.send_frames.pop(0)
                if frame.index >= index:
                    bisect.insort(self.frames, frame)
                    self.write_frame()
        elif action == ACTION_INDEX_RESET:
            self.write_action(ACTION_INDEX_RESET_ACK)
            self.recv_index = 0
        elif action == ACTION_INDEX_RESET_ACK:
            self.send_frames = []
            self.frames += self.wait_reset_frames
            self.wait_reset_frames = None
            if self.frames:
                self.write_frame()
        elif action == ACTION_TTL:
            self.write_action(ACTION_TTL_ACK, data, index=0)
        elif action == ACTION_TTL_ACK:
            start_time, = struct.unpack("!I", data)
            if len(self.ttls) >=3:
                self.ttls.pop(0)
            self.ttls.append((int(time.time() * 1000) & 0xffffffff) - start_time)
            self.ttl = min(max(float(sum(self.ttls)) / float(len(self.ttls)), 50), 4000)
            logging.info("stream session %s center %s ttl %s", self.session, self, self.ttl)

    def write_action(self, action, data, index=None):
        frame = self.create_frame(data, action = action, index = index)
        if self.wait_reset_frames is None:
            bisect.insort(self.frames, frame)
            self.write_frame()
        else:
            bisect.insort(self.wait_reset_frames, frame)

    def write_ack(self):
        data = struct.pack("!I", self.recv_index - 1)
        self.write_action(ACTION_ACK, data, index=0)

    def on_ack_timeout_loop(self, recv_index):
        if self.recv_frames and recv_index == self.recv_index:
            data = struct.pack("!II", recv_index, self.recv_frames[0].index)
            self.write_action(ACTION_RESEND, data, index=0)
        if self.recv_frames and not self.closed:
            current().timeout(self.ttl * 1.2 / 1000, self.on_ack_timeout_loop, self.recv_index)
        else:
            self.ack_timeout_loop = False

    def write_ttl(self):
        for i in range(3):
            data = struct.pack("!I", int(time.time() * 1000) & 0xffffffff)
            self.write_action(ACTION_TTL, data, index=0)
        current().timeout(60, self.write_ttl)

    def close(self):
        if not self.closed:
            self.closed = True
            self.remove_all_listeners()
            logging.info("xstream session %s center %s close", self.session, self)

    def __del__(self):
        self.close()
