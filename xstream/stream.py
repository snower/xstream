# -*- coding: utf-8 -*-
#14-4-22
# create by: snower

from ssloop import EventEmitter

class Stream(EventEmitter):
    def __init__(self, stream_id, session):
        super(Stream, self).__init__()

        self._stream_id = stream_id
        self._session = session

    def on_data(self, data):
        self.emit("data", self, data)

    def write(self, data):
        self._session.write(self, data)