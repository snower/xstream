# -*- coding: utf-8 -*-
#14-4-22
# create by: snower

import time
import random
import math
import logging
import bisect
from collections import deque
from sevent import EventEmitter, current, Buffer
from .frame import StreamFrame
from .crypto import rand_string
from .utils import format_data_len

ACTION_OPEN  = 1
ACTION_OPENED = 2
ACTION_CLIOSE = 3
ACTION_CLIOSED = 4

class Stream(EventEmitter):
    def __init__(self, stream_id, session, is_server = False, priority = 0, capped = False, expried_time = 900):
        super(Stream, self).__init__()

        now = time.time()

        self.loop = current()
        self._stream_id = stream_id
        self._session = session
        self._is_server = is_server
        self._priority = priority
        self._capped = capped
        self._closed = False
        self._expried_time = expried_time
        self._start_time = now

        self._send_index = 1
        self._send_buffer = Buffer()
        self._send_frames = deque()
        self._send_frame_count = 0
        self._send_data_len = 0
        self._send_time = now
        self._send_is_set_ready = False

        self._recv_index = 1
        self._recv_buffer = Buffer()
        self._recv_frames = []
        self._recv_frame_count = 0
        self._recv_data_len = 0
        self._recv_time = now
        self._recv_wait_emit = False

        if self._expried_time:
            self.loop.add_timeout(self._expried_time / 5.0, self.on_time_out_loop)

    @property
    def id(self):
        return self._stream_id

    @property
    def priority(self):
        if self._priority != 0:
            return 0

        t = time.time()
        p = self._send_frame_count * 2.0 / (1 + math.sqrt(t - self._start_time))
        if self._send_is_set_ready:
            if t - self._send_time > 30:
                return 0
            return p / ((1 + t - self._send_time) ** 2)
        return p

    @property
    def capped(self):
        return self._capped

    @property
    def buffer(self):
        return (self._recv_buffer, self._send_buffer)

    def on_data(self):
        self.emit_data(self, self._recv_buffer)
        self._recv_wait_emit = False

    def on_frame(self, frame):
        if frame.index == 0:
            if frame.action == 0:
                self.on_read(frame)
            else:
                self.on_action(frame)
            return

        if frame.index != self._recv_index:
            if frame.index < self._recv_index:
                return

            if not self._recv_frames or frame.index >= self._recv_frames[-1].index:
                self._recv_frames.append(frame)
            else:
                bisect.insort_left(self._recv_frames, frame)
            return

        if frame.action == 0:
            self.on_read(frame)
        else:
            self.on_action(frame)
        self._recv_index += 1

        read_frame_count = 0
        while self._recv_frames:
            frame = self._recv_frames[0]
            if frame.index != self._recv_index:
                if frame.index < self._recv_index:
                    self._recv_frames.pop(0)
                    continue
                break

            self._recv_frames.pop(0)
            if read_frame_count >= 128:
                current().add_async(self.on_frame, frame)
                return

            if frame.action == 0:
                self.on_read(frame)
            else:
                self.on_action(frame)
            self._recv_index += 1
            read_frame_count += 1

    def on_read(self, frame):
        if not self._recv_wait_emit:
            self._recv_wait_emit = True
            self.loop.add_async(self.on_data)
        self._recv_buffer.write(frame.data)
        self._recv_frame_count += 1
        self._recv_data_len += len(frame.data)
        self._recv_time = frame.recv_time

    def remove_send_frame(self, frame):
        try:
            self._send_frames.remove(frame)
        except:pass

    def remove_all_send_frames(self):
        self._send_frames = deque()
        self._send_buffer.read()

    def do_write(self):
        if len(self._send_frames) <= 1 and self._send_buffer:
            if not self._closed:
                self.flush()

        if self._send_frames:
            frame = self._send_frames.popleft()
            if self._send_frame_count == 0 and frame.action == 0 and not self._is_server:
                frame.action = ACTION_OPEN
                if self._priority != 0:
                    frame.flag |= 0x02
                if self._capped:
                    frame.flag |= 0x04
                if self._expried_time == 0:
                    frame.flag |= 0x08

            frame.send_time = time.time()
            self._session.write(frame)
            self._send_frame_count += 1
            self._send_data_len += len(frame)
            self._send_time = frame.send_time

        self._send_is_set_ready = bool(self._send_frames)
        return self._send_is_set_ready
        
    def flush(self, flush_all = False):
        if not self._send_buffer:
            return 

        if self._capped:
            for _ in range(64):
                if self._send_buffer:
                    frame = StreamFrame(self._stream_id, 0, 0, self._send_index, self._send_buffer.next())
                    self._send_index += 1
                    self._send_frames.append(frame)
                else:
                    break
        else:
            for _ in range(64):
                blen = len(self._send_buffer)
                if blen > self._session._mss:
                    frame = StreamFrame(self._stream_id, 0, 0, self._send_index, self._send_buffer.read(self._session._mss))
                    self._send_index += 1
                    self._send_frames.append(frame)
                elif blen > 0 and (flush_all or len(self._send_frames) < 2):
                    frame = StreamFrame(self._stream_id, 0, 0, self._send_index, self._send_buffer.read(-1))
                    self._send_index += 1
                    self._send_frames.append(frame)
                    break
                else:
                    break
            
    def on_write(self):
        if self._send_is_set_ready:
            return

        if self._send_buffer:
            self._send_time = time.time()
            self._send_is_set_ready = True
            if not self._session.ready_write(self):
                self.do_close()

    def write(self, data):
        if not self._closed:
            if not data:
                return

            if data.__class__ == Buffer:
                self._send_buffer.extend(data)
            else:
                self._send_buffer.write(data)

            if not self._send_is_set_ready:
                self.loop.add_async(self.on_write)

    def write_action(self, action, data=b''):
        data += rand_string(random.randint(1, 256 - len(data)))
        frame = StreamFrame(self._stream_id, action, 0, self._send_index, data)
        self._send_index += 1
        frame.send_time = time.time()
        self.loop.add_async(self._session.write, frame)

    def on_action(self, frame):
        if frame.action == ACTION_OPEN:
            if frame.flag & 0x01:
                self.write_action(ACTION_OPENED)

            self.on_read(frame)
        elif frame.action == ACTION_OPENED:
            pass
        elif frame.action == ACTION_CLIOSE:
            if frame.flag & 0x01:
                self.on_read(frame)
            self.write_action(ACTION_CLIOSED)
            self.remove_all_send_frames()
            self.do_close()
        elif frame.action == ACTION_CLIOSED:
            self.do_close()

    def close(self):
        if self._closed:
            return

        self._closed = True

        if self._session.closed or self._send_frame_count <= 0:
            return self.do_close()

        while self._send_buffer:
            self.flush(True)

        if self._send_frames:
            frame = self._send_frames[-1]
            frame.action = ACTION_CLIOSE
            frame.flag = 0x01

            if not self._send_is_set_ready and self._send_frames:
                self._send_time = time.time()
                self._send_is_set_ready = True
                if not self._session.ready_write(self):
                    self.do_close()
        else:
            self.write_action(ACTION_CLIOSE)

        def do_colse_timeout():
            if self._session:
                self.loop.add_timeout(self._expried_time, self.do_close)
        self.loop.add_timeout(5, do_colse_timeout)

    def do_close(self):
        if not self._session:
            return
        
        self._closed = True
        def do_close():
            if self._send_is_set_ready:
                self._session.ready_write(self, False)
                self._send_is_set_ready = False

            session = self._session
            if self._session:
                self.emit_close(self)
                self._session.close_stream(self)
                self.remove_all_listeners()
                self._session = None
            logging.info("xstream session %s stream %s close %s(%s) %s(%s) %.2fms", session, self,
                         format_data_len(self._send_data_len), self._send_frame_count,
                         format_data_len(self._recv_data_len), self._recv_frame_count,
                         (time.time() - self._start_time) * 1000)

        self.loop.add_async(do_close)

    def on_time_out_loop(self):
        if not self._closed:
            if time.time() - max(self._send_time, self._recv_time) > self._expried_time:
                self.close()
            else:
                self.loop.add_timeout(self._expried_time / 5.0, self.on_time_out_loop)

    def __del__(self):
        self.close()

    def __str__(self):
        return "<%s %s>" % (super(Stream, self).__str__(), self._stream_id)
