# -*- coding: utf-8 -*-
#14-4-24
# create by: snower

import threading
import time
import ssloop
from xstream.client import Client

def on_data(stream,data):
    print data,stream
    stream.close()

def on_session(client, session):
    thread.start()

def on_close(stream):
    print stream

def input():
    print "input thread start"
    while True:
        stream= client.session().stream()
        stream.on("data", on_data)
        stream.on("close", on_close)
        data=raw_input("input:")
        stream.write(str(time.time())+" %s client say:"+data)

loop = ssloop.instance()
client = Client('127.0.0.1',20000)
client.on("session", on_session)
thread=threading.Thread(target=input)
client.open()
loop.start()