# -*- coding: utf-8 -*-
#14-5-1
# create by: snower

from ssloop import EventEmitter

class SessionControl(EventEmitter):
    def __init__(self,session,stream):
        self._session=session
        self._stream=stream
        self._is_open=False

        self._stream.on("streaming",self.on_stream_streaming)
        self._session.loop.timeout(5,self.on_timeout)

    def on_stream_streaming(self,stream):
        if stream.id==self._stream.id:
            self._session.streaming()
            self._is_open=True

    def on_timeout(self):
        if not self._is_open:
            self._session.close()