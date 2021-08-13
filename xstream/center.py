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
        self.send_ack_index = 0
        self.ack_loop = False
        self.ack_timeout_loop = False
        self.send_timeout_loop = False
        self.ttl = 50
        self.ttl_index = 0
        self.ttl_changing = False
        self.ttl_remote_delay = 0
        self.closed = False
        self.ready_streams_lookup_timeout = None
        self.droped_count = 0
        self.resended_count = 0
        self.rframe_count = 0
        self.sframe_count = 0
        self.ack_count = 0

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
        if not connection._finaled:
            current().add_timeout(2.2, check_send_frames)

    def create_frame(self, data, action=0, index=None):
        if index is None:
            if self.send_index == 0x7fffffff:
                self.write_action(ACTION_INDEX_RESET, index=self.send_index)
                self.send_index += 1
                logging.info("stream session %s center %s index reset", self.session, self)

            self.send_ack_index = self.recv_index - 1
            frame = Frame(action, self.send_index, self.send_ack_index, data)
            self.send_index += 1
        else:
            self.send_ack_index = self.recv_index - 1
            frame = Frame(action, index, self.send_ack_index, data)
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

        if not self.drain_connections:
            return True
        if self.frames:
            self.write_frame()
            return True
        if not self.ready_streams:
            return True
        self.sort_stream()
        stream = self.ready_streams[0]
        if not stream.do_write():
            self.ready_streams.pop(0)
        return True

    def write(self, data):
        frame = self.create_frame(data)
        if not self.frames or frame.index >= self.frames[-1].index:
            self.frames.append(frame)
        else:
            bisect.insort(self.frames, frame)
        self.write_frame()
        return frame

    def write_frame(self):
        for _ in range(len(self.drain_connections)):
            if not self.frames or self.frames[0].index > 0x7fffffff:
                return
            
            connection = self.drain_connections.popleft()
            if connection._closed:
                continue
            self.write_next(connection)

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

    def write_next(self, connection):
        frame = self.get_write_connection_frame(connection)
        if not frame:
            self.drain_connections.append(connection)
            if self.ready_streams:
                def continue_write_next():
                    if self.ready_streams:
                        stream = self.ready_streams[0]
                        if not stream.do_write():
                            self.ready_streams.pop(0)
                current().add_async(continue_write_next)
            return None

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

        if not connection.write(frame):
            if not self.frames or frame.index >= self.frames[-1].index:
                self.frames.append(frame)
            else:
                bisect.insort(self.frames, frame)
            return None
        self.sframe_count += 1
        return frame

    def on_frame(self, connection, frame):
        frame.recv_time = time.time()
        self.rframe_count += 1

        if frame.ack != self.ack_index:
            self.ack_index = frame.ack
            while self.send_frames and self.send_frames[0].index <= self.ack_index:
                send_frame = self.send_frames.pop(0)
                send_frame.ack_time = time.time()

        if frame.index == 0:
            return self.emit_frame(self, frame)

        if frame.index < self.recv_index or frame.index in self.recv_uframes \
                or abs(frame.index - self.recv_index) > 0x7fffffff:
            self.droped_count += 1
            return

        if frame.index == self.recv_index:
            self.emit_frame(self, frame)
            self.recv_index += 1

            while self.recv_frames and self.recv_frames[0].index <= self.recv_index:
                frame = self.recv_frames[0]
                if frame.index == self.recv_index:
                    if frame.index in self.recv_uframes:
                        self.recv_uframes.pop(self.recv_frames[0].index, None)
                    else:
                        self.emit_frame(self, frame)
                    self.recv_index += 1
                else:
                    self.droped_count += 1
                self.recv_frames.pop(0)

            if not self.ack_loop:
                current().add_timeout(2, self.on_ack_loop, self.sframe_count)
                self.ack_loop = True
        else:
            if not self.recv_frames or frame.index >= self.recv_frames[-1].index:
                self.recv_frames.append(frame)
            else:
                bisect.insort_left(self.recv_frames, frame)
            if frame.action == 0 and (frame.data.flag & 0x02 != 0 or frame.data.stream_id in self.session._streams):
                self.emit_frame(self, frame)
                self.recv_uframes[frame.index] = frame

        if not self.ack_timeout_loop and self.recv_frames:
            current().add_timeout(3, self.on_ack_timeout_loop)
            self.ack_timeout_loop = True

    def on_drain(self, connection):
        self.drain_connections.append(connection)
        if self.frames:
            return self.write_frame()

        while not self.frames and self.ready_streams:
            stream = self.ready_streams[0]
            if not stream.do_write():
                self.ready_streams.pop(0)

    def on_action(self, action, data):
        if action == ACTION_ACK:
            start_time, remote_time = struct.unpack("!QQ", data[:16])
            self.ttl_remote_delay = time.time() * 1000000 - remote_time
            if start_time:
                ack_time = time.time() * 1000 - float(start_time) / 1000
                self.ttl = max(float(self.ttl + ack_time) / 2.0, 50)
        elif action == ACTION_RESEND:
            resend_count, = struct.unpack("!I", data[:4])
            now = time.time()
            resend_frame_ids = []
            waiting_frames = []
            connections = {id(c) for c in self.session._connections} if self.session else set([])

            for i in range(resend_count):
                resend_index, = struct.unpack("!I", data[4 + i * 4: 8 + i * 4])
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
            if self.send_index >= 0x7fffffff:
                self.write_action(ACTION_INDEX_RESET_ACK)
            else:
                self.write_action(ACTION_INDEX_RESET_ACK, index=self.send_index)
                self.send_index += 1
            self.recv_index = 1
            self.send_ack_index = 0
            if self.recv_frames:
                self.recv_frames = []
            if self.recv_uframes:
                self.recv_uframes = {}
            logging.info("stream session %s center %s index reset action", self.session, self)
        elif action == ACTION_INDEX_RESET_ACK:
            self.send_index = 1
            for frame in self.frames:
                if frame.index > 0x7fffffff:
                    frame.index -= 0x7fffffff
                if frame.index + 1 > self.send_index:
                    self.send_index = frame.index + 1
            self.ack_index = 0
            if self.send_frames:
                self.send_frames = []

            if not self.frames and self.ready_streams:
                stream = self.ready_streams[0]
                if not stream.do_write():
                    self.ready_streams.pop(0)

            if self.frames:
                current().add_async(self.write_frame)
            logging.info("stream session %s center %s index reset ack action", self.session, self)
        elif action == ACTION_TTL:
            self.write_action(ACTION_TTL_ACK, data[:12], index=0, sort_ttl=False)
            remote_time, ttl_index, ttl, = struct.unpack("!QII", data[:16])
            self.ttl_remote_delay = time.time() * 1000000 - remote_time
            self.ttl = max((self.ttl + float(ttl) / 1000.0) / 2.0, 50)
            logging.info("stream session %s center passive <%s, (%s %s %s %s) (%s %s %s %s) (%s %s %s %s %s) > ttl %.3fms %s",
                         self.session, self,
                         self.send_index, self.ack_index, len(self.frames), len(self.send_frames),
                         self.recv_index, len(self.recv_frames), self.recv_frames[0].index if self.recv_frames else 0,
                         self.recv_frames[-1].index if self.recv_frames else 0,
                         self.droped_count, self.resended_count, self.sframe_count, self.rframe_count, self.ack_count,
                         self.ttl, self.session.get_ttl_info() if self.session else "")
        elif action == ACTION_TTL_ACK:
            start_time, ttl_index = struct.unpack("!QI", data[:12])
            if ttl_index < self.ttl_index:
                return

            self.on_ttl_ack(time.time() * 1000 - float(start_time) / 1000)

    def write_action(self, action, data=b'', index=None, sort_ttl=True):
        if index is True:
            return self.session.write_action(action, data, index, True)

        data += rand_string(random.randint(1, 256)) if len(data) < 512 else b''
        frame = self.create_frame(data, action=action, index=index)
        if not self.frames or frame.index >= self.frames[-1].index:
            self.frames.append(frame)
        else:
            bisect.insort(self.frames, frame)

        if not sort_ttl:
            self.write_frame()
            return frame

        while self.frames and self.frames[0].index == 0 and self.drain_connections:
            min_ttl_connection = None
            for _ in range(len(self.drain_connections)):
                connection = self.drain_connections.popleft()
                if connection._closed:
                    continue

                if not min_ttl_connection or min_ttl_connection._ttl > connection._ttl:
                    min_ttl_connection = connection
                else:
                    self.drain_connections.append(connection)

            if min_ttl_connection:
                self.write_next(min_ttl_connection)

        if self.frames and self.drain_connections:
            self.write_frame()
        return frame

    def on_ack_loop(self, last_sframe_count=None, start_time=0):
        if self.send_ack_index + 1 == self.recv_index:
            self.ack_loop = False
            return

        now = time.time()
        if self.sframe_count != last_sframe_count:
            current().add_timeout(3, self.on_ack_loop, self.sframe_count, now)
            return

        if self.recv_index - self.send_ack_index <= 8 and (start_time <= 0 or now - start_time < 12):
            current().add_timeout(3, self.on_ack_loop, self.sframe_count, (now - 2) if start_time <= 0 else start_time)
            return

        current().add_timeout(3, self.on_ack_loop, self.sframe_count + 1, now)
        now = int(time.time() * 1000000)
        data = struct.pack("!QQ", int(now - self.ttl_remote_delay) if self.ttl_remote_delay else 0, now)
        self.write_action(ACTION_ACK, data, index=0, sort_ttl=False)
        self.ack_count += 1

    def on_ack_timeout_loop(self):
        if not self.recv_frames or self.closed or not self.session:
            self.ack_timeout_loop = False
            return

        if len(self.session._connections) > 1 and self.ttl < 2200:
            data = []
            current_index, last_index = self.recv_index, self.recv_frames[-1].index

            now = time.time()
            index, cdata, max_timeout = 0, [], max(self.ttl / 500 * 4, 8)
            while current_index <= last_index:
                if index >= len(self.recv_frames):
                    break

                recv_frame = self.recv_frames[index]
                if recv_frame.index < current_index:
                    index += 1
                    continue

                if recv_frame.index == current_index:
                    if cdata and recv_frame.resend_time:
                        if now - recv_frame.resend_time > max_timeout * 2:
                            data.extend(cdata)
                            recv_frame.resend_time = now
                    elif cdata and now - recv_frame.recv_time > max_timeout:
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
                self.write_action(ACTION_RESEND, struct.pack("!I", len(data)) + b"".join(data), index=0)
                current().add_timeout(2, self.on_ack_timeout_loop)
                return
        current().add_timeout(2, self.on_ack_timeout_loop)

    def on_send_timeout_loop(self, frame, ack_index):
        if self.closed:
            return

        if frame.ack_time == 0 and frame.index <= self.ack_index:
            frame.ack_time = time.time()

        if frame.ack_time == 0 and abs(self.ack_index - ack_index) < 250 and len(self.send_frames) >= 32:
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

    def write_ttl(self, last_write_ttl_time=0, last_send_index=0, last_recv_index=0, rewrite_timeout=0):
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
                last_write_ttl_timeout = now - last_write_ttl_time
                if last_write_ttl_timeout >= 3:
                    if p_send_index >= 2872 or p_recv_index >= 2872:
                        require_write = True

                if not require_write and last_write_ttl_timeout >= 8:
                    if self.ttl > 2000:
                        require_write = True
                    elif p_send_index >= 1077 or p_recv_index >= 1077:
                        require_write = True
                    elif len(self.recv_frames) >= 8 and now - self.recv_frames[0].recv_time >= 8:
                        require_write = True
                    elif len(self.send_frames) >= 16 and now - self.send_frames[0].send_time >= 8:
                        require_write = True

                if not require_write and last_write_ttl_timeout >= 13:
                    if self.ttl > 1000:
                        require_write = True
                    elif p_send_index >= 538 or p_recv_index >= 538:
                        require_write = True
                    elif self.recv_frames and len(self.recv_frames) < 8 and now - self.recv_frames[0].recv_time >= 16:
                        require_write = True
                    elif self.send_frames and len(self.send_frames) < 16 and now - self.send_frames[0].send_time >= 16:
                        require_write = True
                    elif len(self.recv_frames) >= 16 and p_recv_index <= 16:
                        require_write = True
                    elif len(self.send_frames) >= 16 and p_send_index <= 16:
                        require_write = True

                if not require_write and last_write_ttl_timeout >= 28:
                    if p_send_index >= 359 or p_recv_index >= 359:
                        require_write = True
                    elif len(self.recv_frames) >= 2 and now - self.recv_frames[0].recv_time >= 43:
                        require_write = True
                    elif len(self.send_frames) >= 4 and now - self.send_frames[0].send_time >= 43:
                        require_write = True

                if not require_write and last_write_ttl_timeout >= 58:
                    if p_send_index >= 179 or p_recv_index >= 179:
                        require_write = True

                if not require_write and last_write_ttl_timeout >= rewrite_timeout:
                    require_write = True
            else:
                require_write = True

            if not require_write:
                return
            self.ttl_index += 1
            if self.ttl_index > 0xffffffff:
                self.ttl_index = 0
            data = struct.pack("!QII", int(now * 1000000), self.ttl_index, int(self.ttl * 1000))
            self.write_action(ACTION_TTL, data, index=0, sort_ttl=False)
            self.ttl_changing = True
            last_write_ttl_time, rewrite_timeout = now, random.randint(300, 600)
        finally:
            current().add_timeout(5, self.write_ttl, last_write_ttl_time, self.send_index,
                                  self.recv_index, rewrite_timeout)

    def on_ttl_ack(self, ack_time):
        self.ttl_changing = False
        self.ttl = max(float(self.ttl + ack_time) / 2.0, 50)
        logging.info("stream session %s center proactive <%s, (%s %s %s %s) (%s %s %s %s) (%s %s %s %s %s) > ttl %.3fms %s", self.session, self,
                     self.send_index, self.ack_index, len(self.frames), len(self.send_frames),
                     self.recv_index, len(self.recv_frames), self.recv_frames[0].index if self.recv_frames else 0,
                     self.recv_frames[-1].index if self.recv_frames else 0,
                     self.droped_count, self.resended_count, self.sframe_count, self.rframe_count, self.ack_count,
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
