#!/usr/bin/env python3
"""
Very simple HTTP server in python for logging requests
Usage::
    ./server.py [<port>]
"""
import os
import string
from http.server import BaseHTTPRequestHandler, HTTPServer
import logging

import re
import requests
import subprocess
from subprocess import PIPE, run

class NumOfVirusNotifiersClass(object):
    num = 2
class MyIdClass(object):
    id = 1

class S(BaseHTTPRequestHandler):
    def _set_response(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        logging.info("GET request,\nPath: %s\nHeaders:\n%s\n", str(self.path), str(self.headers))
        self._set_response()
        self.wfile.write("GET request for {}".format(self.path).encode('utf-8'))

    def do_POST(self):
        content_length = int(self.headers['Content-Length']) # <--- Gets the size of data
        post_data = self.rfile.read(content_length) # <--- Gets the data itself
        postVars = post_data.decode('utf-8')
        postVars = postVars.replace("\"","")
        if re.match(r'^fromNotifier', postVars) is None:
            fileAddr = "/home/ron/PycharmProjects/sdntest/block.list"
            fh = open(fileAddr, "r")
            str = fh.read();
            fh.close()
            blocked_list = str.split(",")
            if postVars not in blocked_list:
                print("writing file")
                fh = open(fileAddr, "w")
                fh.seek(0)
                print("len%d", blocked_list.__len__())
                if len(str) == 0:
                    fh.write(postVars)
                else:
                    blocked_list.append(postVars)
                    fh.write(",".join(blocked_list))
                fh.truncate()
                fh.close()
            for i in range(1,NumOfVirusNotifiersClass.num+1):
                if i==MyIdClass.id: continue
                currentAddr = '10.%d.0.0:8080' % i
                msg = "fromNotifier"+postVars
                subprocess.call(["curl", "-d", "\"" + msg + "\"", "-X", "POST", currentAddr])
                subprocess.call(["curl", "-d", "\"" + msg + "\"", "-X", "POST", currentAddr])
        else:
            postVars = postVars.replace("fromNotifier","")
        #logging.info("POST request,\nPath: %s\nHeaders:\n%s\n\nBody:\n%s\n",
        #        str(self.path), str(self.headers), postVars)

        self._set_response()
        #self.wfile.write("POST request for {}".format(self.path).encode('utf-8'))
        print("host "+postVars+" is attacker!");
        self.wfile.write("Message Received".encode('utf-8'))

def run(server_class=HTTPServer, handler_class=S, port=8080):
    logging.basicConfig(level=logging.INFO)
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    logging.info('Starting httpd...\n')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    logging.info('Stopping httpd...\n')

if __name__ == '__main__':
    from sys import argv

    if len(argv) == 4:
        NumOfVirusNotifiersClass.num = int(argv[2])
        MyIdClass.id = int(argv[3])
        run(port=int(argv[1]))
    else:
        run()