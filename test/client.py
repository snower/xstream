# -*- coding: utf-8 -*-
#14-4-24
# create by: snower

import threading
import time
import ssloop
from xstream.client import Client

def on_data(s,data):
    print data % s


def ready(session):
    stream=session.stream()
    stream.on("data",data)
    stream.write("hello"+str(time.time()))
    stream.close()
    thread.start()

def input():
    print "input thread start"
    stream=client.session().stream()
    stream.on("data", on_data)
    while True:
        data=raw_input("input:")
        stream.write(str(time.time())+" %s client say:"+data)

loop = ssloop.instance()
client = Client('127.0.0.1',20000)
thread=threading.Thread(target=input)
thread.start()
client.open()
loop.start()