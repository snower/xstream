# -*- coding: utf-8 -*-
#14-4-24
# create by: snower

import threading
import time
from session import Session

def data(s,data):
    print data % s


def ready(session):
    stream=session.stream()
    stream.on("data",data)
    stream.write("hello"+str(time.time()))
    stream.close()
    thread.start()

def input():
    print "input thread start"
    while True:
        stream=session.stream()
        data=raw_input("input:")
        if data=="close":
            session.close()
        stream.write(str(time.time())+" %s client say:"+data)
        stream.close()

session=Session('127.0.0.1',20000)
thread=threading.Thread(target=input)
session.on("ready",ready)
session.open()