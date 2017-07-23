# -*- coding: utf-8 -*-
# 14/12/10
# create by: snower

import time
import logging
import struct
import random
import math
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
        self.ack_index = 0
        self.ack_time = 0
        self.ack_loop = False
        self.ack_timeout_loop = False
        self.send_timeout_loop = False
        self.ttls = [0]
        self.ttl = 1000
        self.wait_reset_frames = None
        self.closed = False
        self.writing_connection = None
        self.waiting_read_frame = False

        self.write_ttl()
        current().timeout(2, self.on_ready_streams_lookup)

    def add_connection(self, connection):
        connection.on("frame", self.on_frame)
        connection.on("drain", self.on_drain)
        if self.frames:
            self.writing_connection = connection
            try:
                self.write_next(connection)
            finally:
                self.writing_connection = None
        else:
            while not self.frames and self.wait_reset_frames is None and self.ready_streams:
                stream = self.ready_streams[0]
                if not stream.do_write():
                    self.ready_streams.pop(0)

            if self.frames:
                self.writing_connection = connection
                try:
                    self.write_next(connection)
                finally:
                    self.writing_connection = None
            else:
                self.drain_connections.append(connection)

    def remove_connection(self, connection):
        for send_frame in self.send_frames:
            if connection == send_frame.connection:
                bisect.insort(self.frames, send_frame)
                self.send_frames.remove(send_frame)
        current().async(self.write_frame)

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

    def sort_stream(self):
        def cmp_stream(x, y):
            c = cmp(x.priority, y.priority)
            if c == 0:
                c = cmp(x._start_time, y._start_time)
            return c
        self.ready_streams = sorted(self.ready_streams, cmp_stream)

    def ready_write(self, stream, is_ready=True):
        if self.closed:
            return False

        if not is_ready:
            if stream in self.ready_streams:
                self.ready_streams.remove(stream)
            return

        if stream not in self.ready_streams:
            self.ready_streams.append(stream)

        def do_stream_write():
            if not self.ready_streams:
                return

            self.sort_stream()

            if self.drain_connections and self.wait_reset_frames is None:
                if self.frames:
                    self.write_frame()
                else:
                    stream = self.ready_streams[0]
                    if not stream.do_write():
                        self.ready_streams.pop(0)
        current().async(do_stream_write)
        return True

    def write(self, data):
        frame = self.create_frame(data)
        if self.wait_reset_frames is None:
            bisect.insort(self.frames, frame)
            if not self.writing_connection:
                current().async(self.write_frame)
        else:
            bisect.insort(self.wait_reset_frames, frame)
        return frame

    def write_frame(self):
        for _ in range(len(self.drain_connections)):
            if not self.frames:
                return
            
            connection = self.drain_connections.popleft()
            if not connection._closed:
                self.writing_connection = connection
                try:
                    self.write_next(connection)
                finally:
                    self.writing_connection = None

    def get_write_connection_frame(self, connection):
        frame = self.frames.pop(0)
        if frame.index > 0 and frame.index <= self.ack_index:
            while frame.index > 0 and frame.index <= self.ack_index:
                if not self.frames:
                    return None
                frame = self.frames.pop(0)

        if connection == frame.connection:
            frames = []
            while frame and connection == frame.connection:
                bisect.insort(frames, frame)
                frame = self.frames.pop(0) if self.frames else None
            if frames:
                self.frames = frames + self.frames
        return frame

    def write_next(self, connection, frame = None, first_write = True):
        if frame is None:
            frame = self.get_write_connection_frame(connection)

        if frame:
            if frame.index != 0:
                frame.connection = connection
                frame.send_time = time.time()
                frame.ack_time = 0
                bisect.insort(self.send_frames, frame)

                if not self.send_timeout_loop:
                    for send_frame in self.send_frames:
                        if send_frame.index != 0:
                            current().timeout(max(60, math.sqrt(self.ttl * 20)), self.on_send_timeout_loop, send_frame, self.ack_index)
                            self.send_timeout_loop = True
                            break

            next_data_len = connection.write(frame.dumps())
            if next_data_len > 32:
                def on_write_next_full(self, connection, next_data_len):
                    frame = self.get_write_connection_frame(connection) if self.frames else None
                    while not frame and self.ready_streams and self.wait_reset_frames is None:
                        stream = self.ready_streams[0]
                        if not stream.do_write():
                            self.ready_streams.pop(0)
                        frame = self.get_write_connection_frame(connection) if self.frames else None

                    if frame:
                        if len(frame.data) + 11 <= next_data_len:
                            self.writing_connection = connection
                            try:
                                self.write_next(connection, frame, False)
                            finally:
                                self.writing_connection = None
                        else:
                            bisect.insort(self.frames, frame)
                            connection.flush()
                    else:
                        connection.flush()
                current().async(on_write_next_full, self, connection, next_data_len)
            else:
                connection.flush()
            
        elif first_write:
            self.drain_connections.append(connection)
            if self.ready_streams:
                def on_write_next(self):
                    while self.ready_streams and self.wait_reset_frames is None:
                        stream = self.ready_streams[0]
                        if not stream.do_write():
                            self.ready_streams.pop(0)
                current().async(on_write_next, self)
        return frame

    def on_read_frame(self):
        self.waiting_read_frame = False
        read_frame_count = 0
        while self.recv_frames and self.recv_frames[0].index <= self.recv_index:
            if self.recv_frames[0].index == self.recv_index:
                if read_frame_count >= 64:
                    self.waiting_read_frame = True
                    current().async(self.on_read_frame)
                    return

                self.emit("frame", self, self.recv_frames[0])
                self.recv_index += 1
                read_frame_count += 1
            self.recv_frames.pop(0)

    def on_frame(self, connection, data):
        frame = Frame.loads(data, connection)

        if frame.index == 0:
            return self.emit("frame", self, frame)

        if frame.index < self.recv_index or abs(frame.index - self.recv_index) > 0x7fffffff:
            return

        if frame.index == self.recv_index:
            self.emit("frame", self, frame)
            self.recv_index += 1

            if self.recv_frames and self.recv_frames[0].index <= self.recv_index:
                if not self.waiting_read_frame:
                    self.waiting_read_frame = True
                    current().async(self.on_read_frame)

            if not self.ack_loop:
                current().timeout(1, self.on_ack_loop)
                self.ack_loop = True
        else:
            bisect.insort_left(self.recv_frames, frame)

        if self.recv_frames and not self.ack_timeout_loop:
            current().timeout(min(1, self.ttl * 1.5 / 1000), self.on_ack_timeout_loop, self.recv_index)
            self.ack_timeout_loop = True

    def on_drain(self, connection):
        while not self.frames and self.wait_reset_frames is None and self.ready_streams:
            stream = self.ready_streams[0]
            if not stream.do_write():
                self.ready_streams.pop(0)

        if self.frames:
            self.writing_connection = connection
            try:
                self.write_next(connection)
            finally:
                self.writing_connection = None
        else:
            self.drain_connections.append(connection)

    def on_action(self, action, data):
        if action == ACTION_ACK:
            self.ack_index, = struct.unpack("!I", data[:4])
            while self.send_frames and self.send_frames[0].index <= self.ack_index:
                frame = self.send_frames.pop(0)
                frame.ack_time = time.time()
        elif action == ACTION_RESEND:
            self.ack_index, resend_count = struct.unpack("!II", data[:8])
            while self.send_frames and self.send_frames[0].index <= self.ack_index:
                frame = self.send_frames.pop(0)
                frame.ack_time = time.time()

            now = time.time()
            resend_frame_ids = []
            waiting_frames = []

            for i in range(resend_count):
                resend_index, = struct.unpack("!I", data[8 + i * 4: 12 + i * 4])
                while self.send_frames:
                    frame = self.send_frames.pop(0)
                    if resend_index == frame.index:
                        if now - frame.send_time >= self.ttl / 1000.0 and now - frame.resend_time >= self.ttl / 1000.0 and frame.resend_time <= frame.send_time:
                            bisect.insort(self.frames, frame)
                            resend_frame_ids.append(frame.index)
                            frame.resend_time = now
                            break
                    waiting_frames.append(frame)

            if resend_frame_ids:
                self.write_frame()
            if waiting_frames:
                self.send_frames = waiting_frames + self.send_frames
            logging.info("stream session %s center %s index resend action %s %s %s", self.session, self, self.ack_index, resend_count, resend_frame_ids)
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
            logging.info("stream session %s center <%s, (%s %s %s %s) (%s %s %s %s) > ttl %s", self.session, self,
                         self.send_index, self.ack_index, len(self.frames), len(self.send_frames),
                         self.recv_index, len(self.recv_frames), self.recv_frames[0].index if self.recv_frames else 0, self.recv_frames[-1].index if self.recv_frames else 0,
                         self.ttl)

    def write_action(self, action, data='', index=None):
        if index is True:
            self.session.write_action(action, data, index, True)
        else:
            data += rand_string(random.randint(1, 256))
            frame = self.create_frame(data, action = action, index = index)
            if self.wait_reset_frames is None:
                bisect.insort(self.frames, frame)
                self.write_frame()
            else:
                bisect.insort(self.wait_reset_frames, frame)

    def on_ack_loop(self):
        data = struct.pack("!I", self.recv_index - 1)
        self.write_action(ACTION_ACK, data, index=0)
        self.ack_time = time.time()
        self.ack_loop = False

    def on_ack_timeout_loop(self, recv_index):
        if self.recv_frames and recv_index == self.recv_index:
            data = []
            current_index = self.recv_index
            if self.recv_frames[-1].index - self.recv_index > 64:
                last_index = int(self.recv_index + (self.recv_frames[-1].index - self.recv_index) / 2)
            else:
                last_index = self.recv_frames[-1].index
            index = 0
            while current_index < last_index:
                if self.recv_frames[index].index == current_index:
                    index += 1
                else:
                    data.append(struct.pack("!I", current_index))
                current_index += 1
                if len(data) >= 1024:
                    break

            if len(data) <= 4 or len(data) <= (last_index - self.recv_index) * 0.4:
                self.write_action(ACTION_RESEND, struct.pack("!II", self.recv_index - 1, len(data)) + "".join(data), index=0)
            
        if self.recv_frames and not self.closed:
            current().timeout(min(1, self.ttl * 1.5 / 1000), self.on_ack_timeout_loop, self.recv_index)
        else:
            self.ack_timeout_loop = False

    def on_send_timeout_loop(self, frame, ack_index):
        if frame.ack_time == 0 and abs(self.ack_index - ack_index) < 250 and self.send_frames:
            for send_frame in self.send_frames:
                if frame.connection == send_frame.connection:
                    bisect.insort(self.frames, send_frame)
                    self.send_frames.remove(send_frame)
            if frame.connection and frame.connection._connection:
                connection = frame.connection._connection
                connection.close()
                logging.info("xstream session %s center %s %s send timeout close %s %s %s", self.session, self, connection, frame.index, self.send_index, self.ack_index)
            current().async(self.write_frame)

        if self.send_frames:
            for send_frame in self.send_frames:
                if send_frame.index != 0:
                    current().timeout(min(max(60, math.sqrt(self.ttl * 20) - (time.time() - send_frame.send_time)), 20), self.on_send_timeout_loop, send_frame, self.ack_index)
                    self.send_timeout_loop = True
                    return
        self.send_timeout_loop = False

    def write_ttl(self):
        for i in range(1):
            data = struct.pack("!I", int(time.time() * 1000) & 0xffffffff)
            self.write_action(ACTION_TTL, data, index=0)
        if not self.closed:
            current().timeout(60, self.write_ttl)

    def on_ready_streams_lookup(self):
        self.sort_stream()
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
