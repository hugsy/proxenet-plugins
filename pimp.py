# Proxenet Interaction Module for Python (PIMP)
#
# Small set of functions for parsing easily http request
#

import re

CRLF = "\r\n"


class HTTPRequest :

    def __init__(self, r):
        self.method 	= "GET"
        self.path 	= "/"
        self.version    = "HTTP/1.1"
        self.headers	= {}
        self.body	= ""

        self.parse(r)
        return


    def parse(self, req):
        i = req.find(CRLF*2)
        self.body = req[i+len(CRLF*2):]

        headers = req[:i].split(CRLF)
        parts = re.findall(r"^(?P<method>.+?)\s+(?P<path>.+?)\s+(?P<protocol>.+?)$", headers[0])[0]
        self.method, self.path, self.version = parts

        for header in headers[1:]:
            key, value = re.findall(r"^(?P<key>.+?)\s*:\s*(?P<value>.+?)\s*$", header)[0]
            self.add_header(key, value)
        return


    def has_header(self, key):
        return key.lower() in [ x.lower() in self.headers.keys()]

    def add_header(self, key, value=""):
        self.headers.setdefault(key, value)
        return

    def del_header(self, key):
        self.headers.pop(key, None)
        return

    def update_content_length(self):
        if len(self.body):
            self.add_header("Content-Length", len(self.body))
        return

    def __str__(self):
        req = ""
        self.update_content_length()

        head =  "{0} {1} {2}".format(self.method, self.path, self.version)
        hrds = ["{0}: {1}".format(k,v) for k,v in self.headers.iteritems()]
        data = self.body

        if len(data):
            req = CRLF.join([head, ] + hrds + ['', data])
        else:
            req = CRLF.join([head, ] + hrds + [CRLF, ])

        return req



class HTTPResponse :

    def __init__(self, r):
        self.protocol   = "HTTP/1.1"
        self.status     = 200
        self.reason     = "Ok"
        self.headers    = {}
        self.body       = ""

        self.parse(r)
        return

    def parse(self, res):
        i = res.find(CRLF*2)
        self.body = res[i+len(CRLF*2):]

        headers = res[:i].split(CRLF)
        parts = re.findall(r"^(?P<protocol>.+?)\s+(?P<status>.+?)\s+(?P<reason>.*?)$", headers[0])[0]

        self.protocol, self.status, self.reason = parts

        for header in headers[1:]:
            key, value = re.findall(r"^(?P<key>.+?)\s*:\s*(?P<value>.+?)\s*$", header)[0]
            self.add_header(key, value)

        return

    def has_header(self, key):
        return key.lower() in [ x.lower() in self.headers.keys()]

    def add_header(self, key, value=""):
        self.headers.setdefault(key, value)
        return

    def del_header(self, key):
        self.headers.pop(key)
        return

    def update_content_length(self):
        if len(self.body):
            self.add_header("Content-Length", len(self.body))
        return


    def __str__(self):
        res = ""
        self.update_content_length()

        head = "{0} {1} {2}".format(self.version, self.status, self.reason)
        hrds = ["{0}: {1}".format(k,v) for k,v in self.headers.iteritems()]
        data = self.body

        if len(data):
            res = CRLF.join([head, ] + hrds + ['', data])
        else:
            res = CRLF.join([head, ] + hrds + [CRLF, ])

        return res
