#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler,HTTPServer
import argparse, os, random, sys, requests

from socketserver import ThreadingMixIn
import threading

hostname = 'en.wikipedia.org'

RESPONSE_BLACKLIST=['ASCIS{','ascis{']
PORT_RQ=''
def filterContent(content):
    global PORT_RQ
    print("*********content: ",content)
    with open('log_'+str(PORT_RQ),'a') as f:
        f.writelines(str(PORT_RQ)+':' +str(content)+'\n')
    with open('blacklist.txt','r') as f:
        lines=f.readlines()
        for line in lines:
            line=line.replace('\n','').strip()
            if len(line)>0 and line in content:
                return False
    return True


def merge_two_dicts(x, y):
    return x | y

def set_header():
    headers = {
        'Host': hostname
    }

    return headers

class ProxyHTTPRequestHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.0'
    def do_HEAD(self):
        self.do_GET(body=False)
        return
        
    def do_GET(self, body=True):
        global RESPONSE_BLACKLIST
        sent = False
        try:
            url = 'https://{}{}'.format(hostname, self.path)
            req_header = self.parse_headers()
            if filterContent(url) and  filterContent(req_header) and  filterContent(req_header):           
                resp = requests.get(url, headers=merge_two_dicts(req_header, set_header()), verify=False)
                sent = True

                self.send_response(resp.status_code)
                self.send_resp_headers(resp)
                msg = resp.text
                if body:
                    for flag in RESPONSE_BLACKLIST:
                        if flag in msg:
                            with open('flag','a') as f:
                                f.writelines(str(PORT_RQ)+':' +str(msg)+'\n')
                            msg=msg.replace(flag,"Option")
                    self.wfile.write(msg.encode(encoding='UTF-8',errors='strict'))
                return
        finally:
            if not sent:
                self.send_error(404, 'some error occurred')

    def do_POST(self, body=True):
        sent = False
        try:
            url = 'https://{}{}'.format(hostname, self.path)
            if hasattr(self.headers, 'getheader'):
                content_len = int(self.headers.getheader('content-length', 0))
            else:
                content_len = int(self.headers.get('content-length', 0))
            post_body = self.rfile.read(content_len)
            req_header = self.parse_headers()
            if filterContent(url) and  filterContent(post_body) and  filterContent(req_header):
                resp = requests.post(url, data=post_body, headers=merge_two_dicts(req_header, set_header()), verify=False)
                sent = True
                
                self.send_response(resp.status_code)
                self.send_resp_headers(resp)                
                if body:
                    content=resp.content
                    for flag in RESPONSE_BLACKLIST:
                        if flag in content:
                            with open('flag','a') as f:
                                f.writelines(str(PORT_RQ)+':' +str(content)+'\n')
                            content=content.replace(flag,"Option")
                    self.wfile.write(resp.content)
                return
        finally:
            if not sent:
                self.send_error(404, 'some error occurred')

    def parse_headers(self):
        req_header = {}
        for line in self.headers:
            line_parts = [o.strip() for o in line.split(':', 1)]
            if len(line_parts) == 2:
                req_header[line_parts[0]] = line_parts[1]
        return req_header

    def send_resp_headers(self, resp):
        respheaders = resp.headers
        print ('Response Header')
        for key in respheaders:
            if key not in ['Content-Encoding', 'Transfer-Encoding', 'content-encoding', 'transfer-encoding', 'content-length', 'Content-Length']:
                print (key, respheaders[key])
                self.send_header(key, respheaders[key])
        self.send_header('Content-Length', len(resp.content))
        self.end_headers()

def parse_args(argv=sys.argv[1:]):
    parser = argparse.ArgumentParser(description='Proxy HTTP requests')
    parser.add_argument('--port', dest='port', type=int, default=9999,
                        help='serve HTTP requests on specified port (default: random)')
    parser.add_argument('--hostname', dest='hostname', type=str, default='en.wikipedia.org',
                        help='hostname to be processd (default: en.wikipedia.org)')
    args = parser.parse_args(argv)
    return args

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""

def main(argv=sys.argv[1:]):
    global hostname,PORT_RQ
    args = parse_args(argv)
    hostname = args.hostname
    PORT_RQ=args.port
    print('http server is starting on {} port {}...'.format(args.hostname, args.port))
    server_address = ('127.0.0.1', args.port)
    httpd = ThreadedHTTPServer(server_address, ProxyHTTPRequestHandler)
    print('http server is running as reverse proxy')
    httpd.serve_forever()

if __name__ == '__main__':
    main()
