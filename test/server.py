# -*- coding: utf-8 -*-
#14-4-24
# create by: snower

import time
import ssloop
from xstream.server import Server

#logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)1.1s %(message)s',datefmt='%Y-%m-%d %H:%M:%S', filemode='a+')
def s_close(s):
    print "close:",s

def on_close(s):
    print "close stream:",s

def data(s,data):
    print data % s
    s.write(str(time.time())+" %s server recv")

def stream(session,s):
    print session,s
    s.on("data",data)
    s.on('close',on_close)

def session(server,s):
    print server,s
    s.on("stream",stream)
    s.on("close",s_close)

loop = ssloop.instance()
server=Server(20000)
server.on('session',session)
server.start()
loop.start()