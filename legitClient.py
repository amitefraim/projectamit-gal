#!/usr/bin/env python3
import requests

def httpRequest(msg='default message',addr='http://localhost',port=8080):
    r = requests.post("http://"+addr+':'+str(port), msg)
    print(r.status_code, r.reason)
    print('response from Server\n' + r.text)

if __name__ == '__main__':
    from sys import argv

    if len(argv) == 2: #if only sending message
        print("onearg")
        httpRequest(argv[1])
    elif len(argv) == 4:
        httpRequest(argv[1],argv[2],argv[3])
    else:
        print('Usage: python3 legitClient.py [msg required] [addr optional] [port optional]')