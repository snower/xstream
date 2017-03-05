# -*- coding: utf-8 -*-
#14-4-22
# create by: snower

import time
import random
import math
import logging
from collections import deque
from sevent import EventEmitter, current, Buffer
from frame import StreamFrame
from crypto import  rand_string

ACTION_OPEN  = 1
ACTION_OPENED = 2
ACTION_CLIOSE = 3
ACTION_CLIOSED = 4

class Stream(EventEmitter):
    def __init__(self, stream_id, session, is_server = False, mss = None, priority = 0, capped = False, expried_time = 900):
        super(Stream, self).__init__()

        self.loop = current()
        self._stream_id = stream_id
        self._session = session
        self._is_server = is_server
        self._mss = mss or StreamFrame.FRAME_LEN
        self._priority = priority
        self._capped = capped
        self._closed = False
        self._expried_time = expried_time
        self._start_time = time.time()
        self._data_time = time.time()

        self._send_buffer = None
        self._send_frames = deque()
        self._send_frame_count = 0
        self._send_data_len = 0
        self._send_time = time.time()
        self._send_is_set_ready = False

        self._recv_buffer = Buffer()
        self._recv_frame_count = 0
        self._recv_data_len = 0
        self._recv_time = time.time()
        self._recv_wait_emit = False

        if self._expried_time:
            self.loop.timeout(self._expried_time / 5.0, self.on_time_out_loop)

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

    def on_data(self):
        self.emit("data", self, self._recv_buffer)
        self._recv_wait_emit = False

    def on_frame(self, frame):
        self._data_time = time.time()

        if frame.action == 0:
            self.on_read(frame)
        else:
            self.on_action(frame)

    def on_read(self, frame):
        if not self._recv_wait_emit:
            self._recv_wait_emit = True
            self.loop.async(self.on_data)
        self._recv_buffer.write(frame.data)
        self._recv_frame_count += 1
        self._recv_data_len += len(frame.data)
        self._recv_time = time.time()

    def remove_send_frame(self, frame):
        try:
            self._send_frames.remove(frame)
        except:pass

    def remove_all_send_frames(self):
        self._send_frames = deque()
        self._send_buffer = None

    def do_write(self):
        if self._send_frames:
            frame = self._send_frames.popleft()
            if self._send_frame_count == 0 and frame.action == 0 and not self._is_server:
                frame.action = ACTION_OPEN
                if self._priority != 0:
                    frame.flag |= 0x02
                if self._capped:
                    frame.flag |= 0x04

            self._session.write(frame)
            self._send_frame_count += 1
            self._send_data_len += len(frame)
            self._send_time = time.time()

        if not self._send_frames and self._send_buffer:
            if not self._closed:
                self.flush()

        self._send_is_set_ready = bool(self._send_frames)
        return self._send_is_set_ready
        
    def flush(self):
        if not self._send_buffer:
            return 

        if self._capped:
            for _ in range(64):
                if self._send_buffer:
                    frame = StreamFrame(self._stream_id, 0, 0, self._send_buffer.next())
                    self._send_frames.append(frame)
                else:
                    break
        else:
            for _ in range(64):
                blen = len(self._send_buffer)
                if blen > self._mss:
                    frame = StreamFrame(self._stream_id, 0, 0, self._send_buffer.read(self._mss))
                    self._send_frames.append(frame)
                elif blen > 0:
                    frame = StreamFrame(self._stream_id, 0, 0, self._send_buffer.read(-1))
                    self._send_frames.append(frame)
                    self._send_buffer = None
                    break
                else:
                    break
            
    def on_write(self):
        if self._send_is_set_ready and self._send_frames:
            return
        
        self.flush()

        if not self._send_is_set_ready and self._send_frames:
            self._send_time = time.time()
            self._send_is_set_ready = True
            if not self._session.ready_write(self):
                self.do_close()

    def write(self, data):
        if not self._closed:
            self._data_time = time.time()
            if not data or data == self._send_buffer:
                return

            if isinstance(data, Buffer):
                if not self._send_buffer:
                    self._send_buffer = data
                    self.loop.async(self.on_write)
                else:
                    self._send_buffer.write(data.read(-1))
            else:
                if not self._send_buffer:
                    self._send_buffer = Buffer()
                    self.loop.async(self.on_write)
                self._send_buffer.write(data)

    def write_action(self, action, data=''):
        data += rand_string(random.randint(1, 256 - len(data)))
        frame = StreamFrame(self._stream_id, 0, action, data)
        self.loop.async(self._session.write, frame)

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

        while self._send_buffer:
            self.flush()

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
        self.loop.timeout(self._expried_time, self.do_close)

    def format_data_len(self, data_len):
        if data_len < 1024:
            return "%dB" % data_len
        elif data_len < 1024 * 1024:
            return "%.3fK" % (data_len / 1024.0)
        elif data_len < 1024 * 1024 * 1024:
            return "%.3fM" % (data_len / (1024.0 * 1024.0))

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
                self.emit("close", self)
                self._session.close_stream(self)
                self.remove_all_listeners()
                self._session = None
            logging.info("xstream session %s stream %s close %s(%s) %s(%s) %.2fms", session, self,
                         self.format_data_len(self._send_data_len), self._send_frame_count,
                         self.format_data_len(self._recv_data_len), self._recv_frame_count,
                         (time.time() - self._start_time) * 1000)

        self.loop.async(do_close)

    def on_time_out_loop(self):
        if not self._closed:
            if time.time() - self._data_time > self._expried_time:
                self.close()
            else:
                self.loop.timeout(self._expried_time / 5.0, self.on_time_out_loop)

    def __del__(self):
        self.close()

    def __str__(self):
        return "<%s %s>" % (super(Stream, self).__str__(), self._stream_id)

    def __cmp__(self, other):
        c = cmp(self.priority, other.priority)
        if c == 0:
            c = cmp(self._start_time, other._start_time)
        return c
