# -*- coding: utf-8 -*-
#14-4-24
# create by: snower

import time
import logging
import random
import struct
import socket
from collections import deque
from sevent import EventEmitter, current, Buffer
from crypto import rand_string
from utils import format_data_len

ACTION_PING = 0x01
ACTION_PINGACK = 0x02
ACTION_CLOSE  = 0x03
ACTION_CLOSE_ACK = 0x04
ACTION_NOISE = 0x05

class Connection(EventEmitter):
    def __init__(self, connection, session, mss):
        super(Connection,self).__init__()
        self._connection = connection
        self._session = session
        self._crypto = connection.crypto
        self._mss = mss

        try:
            connection.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            connection.socket.setsockopt(socket.SOL_SOCKET, socket.TCP_KEEPINTVL, 0)
        except: pass

        self._connection.on("close",self.on_close)
        self._connection.on("data",self.on_data)
        self._connection.on("drain",self.on_drain)

        self._read_header = False
        self._start_time = time.time()
        self._data_len = 5
        self._wdata_len = 0
        self._wbuffer = deque()
        self._wait_head = True
        self._closed = False
        self._data_time = time.time()
        self._ping_time = 0
        self._rdata_count = 0
        self._wdata_count = 0
        self._rpdata_count = 0
        self._wpdata_count = 0
        self._rfdata_count = 0
        self._wfdata_count = 0
        self._expried_seconds = random.randint(180, 1800)
        current().timeout(15, self.on_check_data_loop, random.randint(8, 16) * 1024 * 1024)

    def on_data(self, connection, buffer):
        if not self._read_header:
            if len(buffer) < 51:
                return
            buffer.read(51)
            self._read_header = True

        self._data_time = time.time()
        self._rpdata_count += 1
        if buffer._len >= self._data_len:
            self.read(buffer)

    def on_drain(self, connection):
        if not self._closed:
            self.emit("drain", self)

    def on_close(self, connection):
        self.emit("close",self)
        self._closed = True
        self._session, session = None, self._session
        self.remove_all_listeners()
        logging.info("xstream session %s connection %s close %.2fs %s %s %s %s %s %s", session, self,
                     time.time() - self._start_time, 
                     format_data_len(self._rdata_count), self._rfdata_count, self._rpdata_count,
                     format_data_len(self._wdata_count), self._wfdata_count, self._wpdata_count,
                    )

    def read(self, buffer):
        while len(buffer) >= self._data_len:
            data = buffer.read(self._data_len)
            if self._wait_head:
                self._wait_head = False
                self._data_len, = struct.unpack("!H", data[3:])
            else:
                self._wait_head = True
                self._data_len = 5
                data = self._crypto.decrypt(data)

                if data[-2:] != '\x0f\x0f':
                    logging.info("xstream session %s connection %s verify error", self._session, self)
                    return self._connection.close()

                action = ord(data[0])
                if action == 0:
                    self.emit("frame", self, data[1:-2])
                    self._rfdata_count += 1
                else:
                    self.on_action(action, data[1:-2])
                self._rdata_count += len(data) + 5

    def flush(self):
        if not self._closed:
            data = ''
            for feg in self._wbuffer:
                feg = self._crypto.encrypt("".join(['\x00', feg, '\x0f\x0f']))
                feg = "".join(['\x17\x03\x03', struct.pack("!H", len(feg)), feg])
                data += feg

            self._wdata_count += len(data)
            self._wpdata_count += 1
            self._connection.write(data)
            self._wbuffer.clear()
            self._wdata_len = 0

    def write(self, data):
        if not self._closed:
            self._wbuffer.append(data)
            self._wdata_len += len(data) + 8
            self._wfdata_count += 1
            return self._mss - self._wdata_len
        return 0

    def write_action(self, action, data=''):
        data += rand_string(random.randint(1, 1024))
        data = self._crypto.encrypt("".join([struct.pack("!B", action), data, '\x0f\x0f']))
        data = "".join(['\x17\x03\x03', struct.pack("!H", len(data)), data])
        self._wdata_count += len(data)
        self._wpdata_count += 1
        self._wfdata_count += 1
        return self._connection.write(data)

    def on_action(self, action, data):
        if action == ACTION_PING:
            self.write_action(ACTION_PINGACK)
        elif action == ACTION_PINGACK:
            self._ping_time = time.time()
        elif action == ACTION_CLOSE:
            self._closed = True
            self.write_action(ACTION_CLOSE_ACK)
        elif action == ACTION_CLOSE_ACK:
            self._closed = True
            self._connection.close()
            self.remove_all_listeners()

    def on_expried(self):
        if not self._closed:
            self.close()
            logging.info("xstream session %s connection %s expried timeout", self._session, self)

    def on_ping_loop(self):
        if not self._closed:
            if time.time() - self._data_time >= 15:
                self.write_action(ACTION_PING)
                self._ping_time = 0
                current().timeout(2, self.on_ping_timeout)
            else:
                current().timeout(5, self.on_ping_loop)

    def on_ping_timeout(self):
        if not self._closed:
            if self._ping_time == 0:
                self._closed = True
                self._connection.close()
                logging.info("xstream session %s connection %s ping timeout", self._session, self)
            else:
                current().timeout(5, self.on_ping_loop)

    def on_check_data_loop(self, data_count_limit):
        if not self._closed:
            if self._rdata_count > data_count_limit and self._start_time + self._expried_seconds / 2 < time.time():
                self.close()
                logging.info("xstream session %s connection %s data len out", self._session, self)
            else:
                current().timeout(15, self.on_check_data_loop, data_count_limit)

    def close(self):
        if self._closed:
            self._connection.close()
            self.remove_all_listeners()
        else:
            self._closed = True
            self.write_action(ACTION_CLOSE)
            current().timeout(5, self._connection.close)

    def __del__(self):
        self.close()
