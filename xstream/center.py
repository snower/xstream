# -*- coding: utf-8 -*-
# 14/12/10
# create by: snower

import time
import logging
import struct
import random
from collections import deque
import bisect
from sevent import EventEmitter, current
from frame import Frame
from crypto import rand_string

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
        self.ready_streams = []
        self.frames = []
        self.recv_frames = []
        self.recv_index = 1
        self.send_frames = []
        self.send_index = 1
        self.drain_connections = deque()
        self.ack_time = 0
        self.ack_timeout_loop = False
        self.send_timeout_loop = False
        self.ttls = [0]
        self.ttl = 1000
        self.wait_reset_frames = None
        self.closed = False

        self.write_ttl()
        current().timeout(2, self.on_ready_streams_lookup)

    def add_connection(self, connection):
        connection.on("frame", self.on_frame)
        connection.on("drain", self.on_drain)
        if self.frames:
            self.write_next(connection)
        else:
            while not self.frames and self.wait_reset_frames is None and self.ready_streams:
                stream = self.ready_streams[0]
                if not stream.do_write():
                    self.ready_streams.pop(0)

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
                logging.info("stream session %s center %s index reset", self.session, self)
            frame = Frame(1, self.session.id, flag, self.send_index, None, action, data)
            self.send_index += 1
        else:
            frame = Frame(1, self.session.id, flag, index, None, action, data)
        return frame

    def ready_write(self, stream, is_ready=True):
        if self.closed:
            return False

        if not is_ready:
            if stream in self.ready_streams:
                self.ready_streams.remove(stream)
            return

        if stream not in self.ready_streams:
            self.ready_streams.append(stream)
            self.ready_streams = sorted(self.ready_streams)

        if self.drain_connections and self.wait_reset_frames is None:
            stream = self.ready_streams[0]
            if not stream.do_write():
                self.ready_streams.pop(0)
        return True

    def write(self, data):
        frame = self.create_frame(data)
        if self.wait_reset_frames is None:
            bisect.insort(self.frames, frame)
            self.write_frame()
        else:
            bisect.insort(self.wait_reset_frames, frame)
        return frame

    def write_frame(self):
        for _ in range(len(self.drain_connections)):
            connection = self.drain_connections.popleft()
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
                if not self.send_timeout_loop:
                    current().timeout(max(2, self.ttl / 100.0), self.on_send_timeout_loop, self.send_frames[0])
                    self.send_timeout_loop = True
            
        else:
            self.drain_connections.append(connection)
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
            if now_ts - self.ack_time > 1:
                current().async(self.write_ack)
                self.ack_time = now_ts

        if frame:
            bisect.insort_left(self.recv_frames, frame)

        if self.recv_frames and not self.ack_timeout_loop:
            current().timeout(self.ttl * 1.5 / 1000, self.on_ack_timeout_loop, self.recv_index)
            self.ack_timeout_loop = True

    def on_drain(self, connection):
        while not self.frames and self.wait_reset_frames is None and self.ready_streams:
            stream = self.ready_streams[0]
            if not stream.do_write():
                self.ready_streams.pop(0)

        if self.frames:
            self.write_next(connection)
        else:
            self.drain_connections.append(connection)

    def on_action(self, action, data):
        if action == ACTION_ACK:
            index, = struct.unpack("!I", data[:4])
            while self.send_frames and self.send_frames[0].index <= index:
                self.send_frames.pop(0)
        elif action == ACTION_RESEND:
            index, recv_index = struct.unpack("!II", data[:8])
            logging.info("stream session %s center %s index resend action %s %s", self.session, self, index, recv_index)
            recv_index = index + int((recv_index - index) * 0.8)
            while self.send_frames and self.send_frames[0].index <= recv_index:
                frame = self.send_frames.pop(0)
                if frame.index >= index:
                    bisect.insort(self.frames, frame)
                    self.write_frame()
        elif action == ACTION_INDEX_RESET:
            self.write_action(ACTION_INDEX_RESET_ACK)
            self.recv_index = 0
            logging.info("stream session %s center %s index reset action", self.session, self)
        elif action == ACTION_INDEX_RESET_ACK:
            self.send_frames = []
            self.frames += self.wait_reset_frames
            self.wait_reset_frames = None

            if self.ready_streams:
                stream = self.ready_streams[0]
                if not stream.do_write():
                    self.ready_streams.pop(0)

            if self.frames:
                self.write_frame()
            logging.info("stream session %s center %s index reset ack action", self.session, self)
        elif action == ACTION_TTL:
            self.write_action(ACTION_TTL_ACK, data[:4], index=0)
        elif action == ACTION_TTL_ACK:
            start_time, = struct.unpack("!I", data[:4])
            if len(self.ttls) >= 3:
                self.ttls.pop(0)
            self.ttls.append((int(time.time() * 1000) & 0xffffffff) - start_time)
            self.ttl = max(float(sum(self.ttls)) / float(len(self.ttls)), 50)
            logging.info("stream session %s center %s ttl %s", self.session, self, self.ttl)

    def write_action(self, action, data='', index=None):
        data += rand_string(random.randint(1, 1024 - len(data)))
        frame = self.create_frame(data, action = action, index = index)
        if frame.index == 0 or self.wait_reset_frames is None:
            bisect.insort(self.frames, frame)
            self.write_frame()
        else:
            bisect.insort(self.wait_reset_frames, frame)

    def write_ack(self):
        data = struct.pack("!I", self.recv_index - 1)
        self.write_action(ACTION_ACK, data, index=0)

    def on_ack_timeout_loop(self, recv_index, retry_rate = 2):
        if self.recv_frames and recv_index == self.recv_index:
            data = struct.pack("!II", recv_index, self.recv_frames[0].index)
            self.write_action(ACTION_RESEND, data, index=0)
        else:
            retry_rate = 2
            
        if self.recv_frames and not self.closed:
            current().timeout(self.ttl * retry_rate / 1000, self.on_ack_timeout_loop, self.recv_index, retry_rate * 2)
        else:
            self.ack_timeout_loop = False

    def on_send_timeout_loop(self, frame):
        if self.send_frames:
            if frame == self.send_frames[0]:
                bisect.insort(self.frames, frame)
                self.send_frames.pop(0)
                if frame.connection and frame.connection._connection:
                    frame.connection._connection.close()
                current().async(self.write_frame)

        if self.send_frames:
            current().timeout(max(2, self.ttl / 100.0), self.on_send_timeout_loop, self.send_frames[0])
        else:
            self.send_timeout_loop = False

    def write_ttl(self):
        for i in range(1):
            data = struct.pack("!I", int(time.time() * 1000) & 0xffffffff)
            self.write_action(ACTION_TTL, data, index=0)
        if not self.closed:
            current().timeout(60, self.write_ttl)

    def on_ready_streams_lookup(self):
        self.ready_streams = sorted(self.ready_streams)
        if not self.closed:
            current().timeout(1, self.on_ready_streams_lookup)

    def close(self):
        if not self.closed:
            while self.ready_streams:
                stream = self.ready_streams.pop(0)
                stream.do_close()
            self.closed = True
            self.remove_all_listeners()
            logging.info("xstream session %s center %s close", self.session, self)

    def __del__(self):
        self.close()
