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

STATE_INITED = 0x01
STATE_OPENED = 0x02
STATE_CLOSED = 0x04

FLAG_DATA = 0x01
FLAG_OPEN = 0x02
FLAG_CLOSE = 0x04
FLAG_NONE_PRIORITY = 0x10
FLAG_CAPPED = 0x20
FLAG_NONE_EXPRIED = 0x40

class Stream(EventEmitter):
    def __init__(self, stream_id, session, is_server=False, priority=0, capped=False, expried_time=900):
        super(Stream, self).__init__()

        now = time.time()

        self.loop = current()
        self._stream_id = stream_id
        self._session = session
        self._is_server = is_server
        self._priority = priority
        self._capped = capped
        self._state = STATE_INITED if not is_server else STATE_OPENED
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
            self._expried_timer = self.loop.add_timeout(self._expried_time / 5.0, self.on_time_out_loop)
        else:
            self._expried_timer = None

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
        self._recv_wait_emit = False
        self.emit_data(self, self._recv_buffer)

    def on_frame(self, frame):
        if frame.index == 0:
            if frame.flag & 0xfe != 0:
                self.on_action(frame)
            if frame.flag & 0x01 != 0:
                self.on_read(frame)
            return

        if frame.index != self._recv_index:
            if not self._recv_frames or frame.index >= self._recv_frames[-1].index:
                self._recv_frames.append(frame)
            else:
                bisect.insort_left(self._recv_frames, frame)

            if self._capped and frame.flag & 0x01 != 0:
                self.on_read(frame)
            return

        if frame.flag & 0xfe != 0:
            self.on_action(frame)
        if frame.flag & 0x01 != 0:
            self.on_read(frame)
        self._recv_index += 1

        while self._recv_frames:
            frame = self._recv_frames[0]
            if frame.index != self._recv_index:
                break

            self._recv_frames.pop(0)
            if frame.flag & 0xfe != 0:
                self.on_action(frame)
            if not self._capped and frame.flag & 0x01 != 0:
                self.on_read(frame)
            self._recv_index += 1

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
        if not self._send_frames:
            if not self._send_buffer:
                self._send_is_set_ready = False
                return self._send_is_set_ready
            self.flush()

        if self._send_frames:
            frame = self._send_frames.popleft()
            frame.send_time = time.time()
            if self._state == STATE_INITED:
                frame.flag |= FLAG_OPEN
                if self._priority != 0:
                    frame.flag |= FLAG_NONE_PRIORITY
                if self._capped:
                    frame.flag |= FLAG_CAPPED
                if self._expried_time == 0:
                    frame.flag |= FLAG_NONE_EXPRIED
                if self._session.write(frame):
                    self._state = STATE_OPENED
            else:
                self._session.write(frame)
            self._send_frame_count += 1
            self._send_data_len += len(frame)
            self._send_time = frame.send_time

        if not self._send_frames and not self._send_buffer:
            self._send_is_set_ready = False
        return self._send_is_set_ready
        
    def flush(self, flush_all=False):
        if self._capped:
            for _ in range(64):
                if not self._send_buffer:
                    break
                frame = StreamFrame(self._stream_id, 0x01, self._send_index, self._send_buffer.next())
                self._send_index += 1
                self._send_frames.append(frame)
        else:
            for _ in range(64):
                blen = len(self._send_buffer)
                if blen >= self._session._mss:
                    frame = StreamFrame(self._stream_id, 0x01, self._send_index, self._send_buffer.read(self._session._mss))
                    self._send_index += 1
                    self._send_frames.append(frame)
                    continue
                elif blen > 0 and (not self._send_frames or flush_all):
                    frame = StreamFrame(self._stream_id, 0x01, self._send_index, self._send_buffer.read(-1))
                    self._send_index += 1
                    self._send_frames.append(frame)
                break

    def write(self, data):
        if self._state == STATE_CLOSED or not data:
            return

        if data.__class__ == Buffer:
            self._send_buffer.extend(data)
        else:
            self._send_buffer.write(data)
        if not self._send_is_set_ready:
            self._send_time = time.time()
            self._send_is_set_ready = True
            if not self._session.ready_write(self):
                self.loop.add_async(self.do_close)

    def write_action(self, action, data=b''):
        data += rand_string(random.randint(1, 128))
        frame = StreamFrame(self._stream_id, action, self._send_index, data)
        self._send_index += 1
        frame.send_time = time.time()
        self.loop.add_async(self._session.write, frame)

    def on_action(self, frame):
        if frame.flag & FLAG_OPEN != 0:
            if self._state == STATE_INITED:
                self._state = STATE_OPENED
        if frame.flag & FLAG_CLOSE != 0:
            def do_close():
                if self._state == STATE_OPENED:
                    self.write_action(FLAG_CLOSE)
                    self.remove_all_send_frames()
                self.do_close()
            self.loop.add_async(do_close)
        if frame.flag & FLAG_NONE_PRIORITY != 0:
            self._priority = 0
        if frame.flag & FLAG_CAPPED != 0:
            self._capped = True
        if frame.flag & FLAG_NONE_EXPRIED != 0:
            self._expried_time = 0

    def close(self):
        if self._state == STATE_CLOSED:
            return

        if self._session.closed or self._state != STATE_OPENED:
            self._state = STATE_CLOSED
            return self.do_close()

        self._state = STATE_CLOSED
        while self._send_buffer:
            self.flush(True)

        if self._send_frames:
            frame = self._send_frames[-1]
            frame.flag |= FLAG_CLOSE

            if not self._send_is_set_ready and self._send_frames:
                self._send_time = time.time()
                self._send_is_set_ready = True
                if not self._session.ready_write(self):
                    return self.do_close()
        else:
            self.write_action(FLAG_CLOSE)

        def do_colse_timeout():
            if self._session:
                self.loop.add_timeout(self._expried_time, self.do_close)
        self.loop.add_timeout(5, do_colse_timeout)

    def do_close(self):
        if not self._session:
            return
        
        self._state = STATE_CLOSED
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
            if self._expried_timer:
                self.loop.cancel_timeout(self._expried_timer)
                self._expried_timer = None
            logging.info("xstream session %s stream %s close %s(%s) %s(%s) %.2fms", session, self,
                         format_data_len(self._send_data_len), self._send_frame_count,
                         format_data_len(self._recv_data_len), self._recv_frame_count,
                         (time.time() - self._start_time) * 1000)
        self.loop.add_async(do_close)

    def on_time_out_loop(self):
        if self._state == STATE_CLOSED or self._expried_time == 0:
            return

        if time.time() - max(self._send_time, self._recv_time) > self._expried_time:
            self.close()
        else:
            self._expried_timer = self.loop.add_timeout(self._expried_time / 5.0, self.on_time_out_loop)

    def __del__(self):
        self.close()

    def __str__(self):
        return "<%s %s>" % (super(Stream, self).__str__(), self._stream_id)
