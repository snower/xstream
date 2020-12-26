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
from .frame import Frame
from .crypto import rand_string

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
        self.recv_uframes = {}
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
        self.ttl_index = 0
        self.ttl_changing = False
        self.wait_reset_frames = None
        self.closed = False
        self.writing_connection = None
        self.waiting_read_frame = False
        self.ready_streams_lookup_timeout = None
        self.droped_count = 0
        self.resended_count = 0
        self.merged_count = 0

        self.write_ttl()

    def add_connection(self, connection):
        connection.on("frame", self.on_frame)
        connection.on("drain", self.on_drain)

    def remove_connection(self, connection):
        def check_send_frames():
            send_frames, send_count = [], 0
            connections = {id(c) for c in self.session._connections} if self.session else set([])
            for send_frame in self.send_frames:
                if connection != send_frame.connection:
                    send_frames.append(send_frame)
                    continue

                if connection._finaled and send_frame.index <= connection._wlast_index:
                    send_frames.append(send_frame)
                    continue

                if not (connections - send_frame.used_connections):
                    send_frames.append(send_frame)
                    continue

                if not self.frames or send_frame.index >= self.frames[-1].index:
                    self.frames.append(send_frame)
                else:
                    bisect.insort(self.frames, send_frame)
                send_count += 1

            self.send_frames = send_frames
            if send_count:
                current().add_async(self.write_frame)

        if connection in self.drain_connections:
            self.drain_connections.remove(connection)
        current().add_timeout(2.2, check_send_frames)

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
        self.ready_streams = sorted(self.ready_streams, key=lambda s: s.priority)

    def ready_write(self, stream, is_ready=True):
        if self.closed:
            return False

        if not is_ready:
            if stream in self.ready_streams:
                self.ready_streams.remove(stream)
            return

        if stream not in self.ready_streams:
            self.ready_streams.append(stream)
            if not self.ready_streams_lookup_timeout and len(self.ready_streams) > 1:
                self.ready_streams_lookup_timeout = current().add_timeout(2, self.on_ready_streams_lookup)

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
        current().add_async(do_stream_write)
        return True

    def write(self, data):
        frame = self.create_frame(data)
        if self.wait_reset_frames is None:
            if not self.frames or frame.index >= self.frames[-1].index:
                self.frames.append(frame)
            else:
                bisect.insort(self.frames, frame)
            if not self.writing_connection:
                self.write_frame()
        else:
            if not self.wait_reset_frames or frame.index >= self.wait_reset_frames[-1].index:
                self.wait_reset_frames.append(frame)
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
        while frame.index <= self.ack_index and frame.index > 0:
            if not self.frames:
                return None
            frame = self.frames.pop(0)

        if id(connection) in frame.used_connections:
            frames = []
            while frame and id(connection) in frame.used_connections:
                if not frames or frame.index >= frames[-1].index:
                    frames.append(frame)
                else:
                    bisect.insort(frames, frame)
                frame = self.frames.pop(0) if self.frames else None
            self.frames = frames + self.frames
        return frame

    def write_next(self, connection, frame=None, first_write=True):
        if frame is None:
            frame = self.get_write_connection_frame(connection)

        if frame:
            frame.connection = connection
            if frame.index != 0:
                frame.used_connections.add(id(connection))
                frame.send_time = time.time()
                frame.ack_time = 0
                if not self.send_frames or frame.index >= self.send_frames[-1].index:
                    self.send_frames.append(frame)
                else:
                    bisect.insort(self.send_frames, frame)

                if not self.send_timeout_loop:
                    for send_frame in self.send_frames:
                        if send_frame.index != 0:
                            current().add_timeout(min(60, math.sqrt(self.ttl * 20)), self.on_send_timeout_loop, send_frame, self.ack_index)
                            self.send_timeout_loop = True
                            break

            next_data_len = connection.write(frame)
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
                                self.merged_count += 1
                            finally:
                                self.writing_connection = None
                        else:
                            if not self.frames or frame.index >= self.frames[-1].index:
                                self.frames.append(frame)
                            else:
                                bisect.insort(self.frames, frame)
                            connection.flush()
                    else:
                        connection.flush()
                current().add_async(on_write_next_full, self, connection, next_data_len)
            else:
                connection.flush()
            
        elif first_write:
            self.drain_connections.append(connection)
            if self.ready_streams and self.wait_reset_frames is None:
                stream = self.ready_streams[0]
                if not stream.do_write():
                    self.ready_streams.pop(0)
                current().add_async(self.write_frame)
        return frame

    def on_read_frame(self):
        self.waiting_read_frame = False
        read_frame_count = 0
        while self.recv_frames and self.recv_frames[0].index <= self.recv_index:
            frame = self.recv_frames[0]
            if frame.index == self.recv_index:
                if read_frame_count >= 128:
                    self.waiting_read_frame = True
                    current().add_async(self.on_read_frame)
                    return

                if frame.index in self.recv_uframes:
                    self.recv_uframes.pop(self.recv_frames[0].index, None)
                else:
                    self.emit_frame(self, frame)
                self.recv_index += 1
                read_frame_count += 1
            else:
                self.droped_count += 1
            self.recv_frames.pop(0)

    def on_frame(self, connection, frame):
        frame.recv_time = time.time()

        if frame.index == 0:
            return self.emit_frame(self, frame)

        if frame.index < self.recv_index or frame.index in self.recv_uframes \
                or abs(frame.index - self.recv_index) > 0x7fffffff:
            self.droped_count += 1
            return

        if frame.index == self.recv_index:
            self.emit_frame(self, frame)
            self.recv_index += 1

            if self.recv_frames and self.recv_frames[0].index <= self.recv_index:
                if not self.waiting_read_frame:
                    self.waiting_read_frame = True
                    current().add_async(self.on_read_frame)

            if not self.ack_loop:
                current().add_timeout(1, self.on_ack_loop)
                self.ack_loop = True
        else:
            if not self.recv_frames or frame.index >= self.recv_frames[-1].index:
                self.recv_frames.append(frame)
            else:
                bisect.insort_left(self.recv_frames, frame)
            if frame.action == 0 and (frame.data.action == 0x01 or frame.data.stream_id in self.session._streams):
                self.emit_frame(self, frame)
                self.recv_uframes[frame.index] = frame

        if not self.ack_timeout_loop and self.recv_frames:
            current().add_timeout(3, self.on_ack_timeout_loop)
            self.ack_timeout_loop = True

    def on_drain(self, connection):
        self.drain_connections.append(connection)

        if self.frames:
            if not self.writing_connection:
                self.write_frame()
        else:
            while not self.frames and self.wait_reset_frames is None and self.ready_streams:
                stream = self.ready_streams[0]
                if not stream.do_write():
                    self.ready_streams.pop(0)

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
            connections = {id(c) for c in self.session._connections} if self.session else set([])

            for i in range(resend_count):
                resend_index, = struct.unpack("!I", data[8 + i * 4: 12 + i * 4])
                while self.send_frames:
                    frame = self.send_frames.pop(0)
                    if resend_index == frame.index:
                        if frame.resend_count >= 60:
                            return self.session.close()

                        if now - frame.send_time >= self.ttl / 1000.0 and now - frame.resend_time >= self.ttl / 1000.0 \
                                and frame.resend_time <= frame.send_time and (connections - frame.used_connections):
                            if not self.frames or frame.index >= self.frames[-1].index:
                                self.frames.append(frame)
                            else:
                                bisect.insort(self.frames, frame)
                            resend_frame_ids.append(frame.index)
                            frame.resend_time = now
                            frame.resend_count += 1
                            self.resended_count += 1
                            break
                        waiting_frames.append(frame)
                        break
                    waiting_frames.append(frame)

            if waiting_frames:
                self.send_frames = waiting_frames + self.send_frames
            if resend_frame_ids:
                current().add_async(self.write_frame)
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
                current().add_async(self.write_frame)
            logging.info("stream session %s center %s index reset ack action", self.session, self)
        elif action == ACTION_TTL:
            self.write_action(ACTION_TTL_ACK, data[:12], index=0)
        elif action == ACTION_TTL_ACK:
            start_time, ttl_index = struct.unpack("!QI", data[:12])
            if ttl_index < self.ttl_index:
                return

            self.on_ttl_ack(time.time() * 1000 - float(start_time) / 1000)

    def write_action(self, action, data=b'', index=None):
        if index is True:
            return self.session.write_action(action, data, index, True)

        data += rand_string(random.randint(1, 256)) if len(data) < 512 else b''
        frame = self.create_frame(data, action=action, index=index)
        if self.wait_reset_frames is None:
            if not self.frames or frame.index >= self.frames[-1].index:
                self.frames.append(frame)
            else:
                bisect.insort(self.frames, frame)
            self.write_frame()
        else:
            if not self.wait_reset_frames or frame.index >= self.wait_reset_frames[-1].index:
                self.wait_reset_frames.append(frame)
            else:
                bisect.insort(self.wait_reset_frames, frame)
        return frame

    def on_ack_loop(self, frame=None, last_ack_index=None):
        if frame:
            if not frame.connection:
                frame.data = b"".join([struct.pack("!I", self.recv_index - 1), rand_string(random.randint(1, 256))])
                self.write_frame()
                self.ack_time = time.time()
                self.ack_loop = False
                return

            if last_ack_index == self.recv_index:
                self.ack_time = time.time()
                self.ack_loop = False
                return

        data = struct.pack("!I", self.recv_index - 1)
        frame = self.create_frame(data, action=ACTION_ACK, index=0)
        if self.wait_reset_frames is None:
            if not self.frames or frame.index >= self.frames[-1].index:
                self.frames.append(frame)
            else:
                bisect.insort(self.frames, frame)
        else:
            if not self.wait_reset_frames or frame.index >= self.wait_reset_frames[-1].index:
                self.wait_reset_frames.append(frame)
            else:
                bisect.insort(self.wait_reset_frames, frame)
        current().add_timeout(1, self.on_ack_loop, frame, self.recv_index)

    def on_ack_timeout_loop(self):
        if not self.recv_frames or self.closed or not self.session:
            self.ack_timeout_loop = False
            return

        if len(self.session._connections) > 1 and self.ttl < 2000:
            data = []
            current_index, last_index = self.recv_index, self.recv_frames[-1].index

            now = time.time()
            index, cdata, max_timeout = 0, data, max(self.ttl / 500 * 3, 5)
            while current_index <= last_index:
                if index >= len(self.recv_frames):
                    break

                recv_frame = self.recv_frames[index]
                if recv_frame.index < current_index:
                    index += 1
                    continue

                if recv_frame.index == current_index:
                    if not cdata:
                        index += 1
                        continue

                    if recv_frame.resend_time:
                        if now - recv_frame.resend_time > max_timeout * 2:
                            data.extend(cdata)
                            recv_frame.resend_time = now
                    else:
                        if now - recv_frame.recv_time > max_timeout:
                            data.extend(cdata)
                            recv_frame.resend_time = now

                    cdata = []
                    index += 1
                else:
                    cdata.append(struct.pack("!I", current_index))
                current_index += 1
                if len(data) >= 5776:
                    break

            if len(data) > 0:
                self.write_action(ACTION_RESEND, struct.pack("!II", self.recv_index - 1, len(data)) + b"".join(data), index=0)
                current().add_timeout(2, self.on_ack_timeout_loop)
                return
        current().add_timeout(2, self.on_ack_timeout_loop)

    def on_send_timeout_loop(self, frame, ack_index):
        if self.closed:
            return

        if frame.ack_time == 0 and frame.index <= self.ack_index:
            frame.ack_time = time.time()

        if frame.ack_time == 0 and abs(self.ack_index - ack_index) < 250 and self.send_frames:
            send_frames = []
            send_count = 0
            connections = {id(c) for c in self.session._connections} if self.session else set([])
            for send_frame in self.send_frames:
                if frame.connection == send_frame.connection and send_count < 32 and (connections - frame.used_connections):
                    if not self.frames or send_frame.index >= self.frames[-1].index:
                        self.frames.append(send_frame)
                    else:
                        bisect.insort(self.frames, send_frame)
                    send_count += 1
                    self.resended_count += 1
                else:
                    send_frames.append(send_frame)
            self.send_frames = send_frames
            if frame.connection and frame.connection._connection and frame.send_timeout_count >= 2:
                connection = frame.connection._connection
                connection.close()
                logging.info("xstream session %s center %s %s send timeout close %s %s %s %s", self.session, self, connection, frame.index, self.send_index, self.ack_index, frame.send_timeout_count)
            current().add_async(self.write_frame)

        if self.send_frames:
            for send_frame in self.send_frames:
                if send_frame.index != 0:
                    current().add_timeout(max(min(60, math.sqrt(self.ttl * 20) - (time.time() - send_frame.send_time)), 20), self.on_send_timeout_loop, send_frame, self.ack_index)
                    self.send_timeout_loop = True
                    send_frame.send_timeout_count += 1
                    return
        self.send_timeout_loop = False

    def write_ttl(self, last_write_ttl_time=0, last_send_index=0, last_recv_index=0):
        if self.closed:
            return

        try:
            if self.ttl_changing:
                self.on_ttl_ack(5000)

            now = time.time()
            require_write = False

            if last_write_ttl_time and last_send_index and last_recv_index:
                p_send_index = self.send_index - last_send_index
                p_recv_index = self.recv_index - last_recv_index
                if self.ttl > 2000 and now - last_write_ttl_time >= 8:
                    require_write = True
                elif self.ttl > 1000 and now - last_write_ttl_time >= 13:
                    require_write = True
                elif (p_send_index >= 2872 or p_recv_index >= 2872) and now - last_write_ttl_time >= 3:
                    require_write = True
                elif (p_send_index >= 718 or p_recv_index >= 718) and now - last_write_ttl_time >= 8:
                    require_write = True
                elif (p_send_index >= 100 or p_recv_index >= 100) and now - last_write_ttl_time >= 13:
                    require_write = True
                elif (p_send_index >= 20 or p_recv_index >= 20) and now - last_write_ttl_time >= 28:
                    require_write = True
                elif now - last_write_ttl_time >= random.randint(58, 118):
                    require_write = True
                elif len(self.recv_frames) >= 16 and p_recv_index < 16 and now - last_write_ttl_time >= 8 and self.ttl < 1000:
                    require_write = True
            else:
                require_write = True

            if require_write:
                self.ttl_index += 1
                if self.ttl_index > 0xffffffff:
                    self.ttl_index = 0
                data = struct.pack("!QI", int(now * 1000000), self.ttl_index)
                self.write_action(ACTION_TTL, data, index=0)
                self.ttl_changing = True
                last_write_ttl_time = now
        finally:
            current().add_timeout(5, self.write_ttl, last_write_ttl_time, self.send_index, self.recv_index)

    def on_ttl_ack(self, ack_time):
        self.ttl_changing = False
        if len(self.ttls) >= 3:
            self.ttls.pop(0)
        self.ttls.append(ack_time)
        self.ttl = max(float(sum(self.ttls)) / float(len(self.ttls)), 50)
        logging.info("stream session %s center <%s, (%s %s %s %s) (%s %s %s %s) (%s %s %s) > ttl %.3fms %s", self.session, self,
                     self.send_index, self.ack_index, len(self.frames), len(self.send_frames),
                     self.recv_index, len(self.recv_frames), self.recv_frames[0].index if self.recv_frames else 0,
                     self.recv_frames[-1].index if self.recv_frames else 0,
                     self.droped_count, self.resended_count, self.merged_count,
                     self.ttl, self.session.get_ttl_info() if self.session else "")

    def on_ready_streams_lookup(self):
        self.sort_stream()
        if self.ready_streams and len(self.ready_streams) > 1 and not self.closed:
            self.ready_streams_lookup_timeout = current().add_timeout(1, self.on_ready_streams_lookup)
        else:
            self.ready_streams_lookup_timeout = None

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
