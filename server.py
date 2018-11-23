#!/usr/bin/env python3
"""
Very simple HTTP server in python for logging requests
Usage::
    ./server.py [<port>]
"""
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
import logging
import requests
import subprocess
from subprocess import PIPE, run

class virusNotifierAddrClass(object):
    addr = "10.1.0.0"

class S(BaseHTTPRequestHandler):
    def _set_response(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        logging.info("GET request,\nPath: %s\nHeaders:\n%s\n", str(self.path), str(self.headers))
        self._set_response()
        self.wfile.write("Welcome to our website, you legitimate User! GET request for {}".format(self.path).encode('utf-8'))

    def do_POST(self):
        content_length = int(self.headers['Content-Length']) # <--- Gets the size of data
        post_data = self.rfile.read(content_length) # <--- Gets the data itself
        postVars = post_data.decode('utf-8')
        #logging.info("POST request,\nPath: %s\nHeaders:\n%s\n\nBody:\n%s\n",
        #        str(self.path), str(self.headers), postVars)

        self._set_response()
        print("Received Message: %s" %(postVars))
        #self.wfile.write("POST request for {}".format(self.path).encode('utf-8'))
        if postVars=="virus":
            command = ['arp','-a', str(self.client_address[0])]
            output = subprocess.check_output(command)
            splittedOutput = output.split()
            originMAC = str(splittedOutput[3].decode('UTF-8'))
            print("Origin MAC: "+ originMAC )
            notifierAddr = "http://"+virusNotifierAddrClass.addr+":8080"
            subprocess.call(["curl", "-d", "\"" + originMAC + "\"", "-X", "POST", notifierAddr])
            subprocess.call(["curl", "-d", "\"" + originMAC + "\"", "-X", "POST", notifierAddr])
            #print("PATH "+str(self.client_address[0]))
            #call(['arp','-a', str(self.client_address[0])])#,'|','cut','-d','\' \'','-f4')
            #call(["curl", "-d", "\"servermsg\"", "-X", "POST", "http://10.0.0.2:8080"])
            retSTR = "You are "+originMAC+", and you have sent a virus\n"
            self.wfile.write(retSTR.encode('utf-8'))
        else:
            self.wfile.write("Legit\n".encode('utf-8'))


def run(server_class=HTTPServer, handler_class=S, port=8080, virusNotifierAddr='10.1.0.0'):
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

    if len(argv) == 3:
        virusNotifierAddrClass.addr=argv[2]
        run(port=int(argv[1]))
    else:
        run()