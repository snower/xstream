# -*- coding: utf-8 -*-
#14-4-22
# create by: snower

from collections import deque
from ssloop import EventEmitter, current
from frame import StreamFrame

ACTION_CLIOSE = 1
ACTION_CLIOSED = 2

class Stream(EventEmitter):
    def __init__(self, stream_id, session):
        super(Stream, self).__init__()

        self.loop = current()
        self._stream_id = stream_id
        self._session = session
        self._closed = False
        self._recv_buffer = None
        self._send_buffer = None

    @property
    def id(self):
        return self._stream_id

    def on_data(self):
        self.emit("data", self, "".join(self._recv_buffer))
        self._recv_buffer = None

    def on_frame(self, frame):
        if frame.action == 0:
            if self._recv_buffer is None:
                self._recv_buffer = deque()
                self.loop.sync(self.on_data)
            self._recv_buffer.append(frame.data)
        else:
            self.on_action(frame.action, frame.data)

    def on_write(self):
        data = "".join(self._send_buffer)
        for i in range(int(len(data) / StreamFrame.FRAME_LEN) + 1):
            frame = StreamFrame(self._stream_id, 0, 0, data[i * StreamFrame.FRAME_LEN: (i+1) * StreamFrame.FRAME_LEN])
            self._session.write(frame)

    def write(self, data):
        if not self._closed:
            if self._send_buffer is None:
                self._send_buffer = deque()
                self.loop.sync(self.on_write)
            self._send_buffer.append(data)

    def write_action(self, action, data=''):
        frame = StreamFrame(self._stream_id, 0, action, data)
        self._session.write(frame)

    def on_action(self, action, data):
        if action == ACTION_CLIOSE:
            self.write_action(ACTION_CLIOSED)
            self.do_close()
        elif action == ACTION_CLIOSED:
            self.do_close()

    def close(self):
        self._closed = True
        self.write_action(ACTION_CLIOSE)

    def do_close(self):
        self._closed = True
        self.emit("close", self)
        self._session.close_stream(self)
        self.remove_all_listeners()
        self._session = None

    def __str__(self):
        return "<%s %s>" % (super(Stream, self).__str__(), self._stream_id)