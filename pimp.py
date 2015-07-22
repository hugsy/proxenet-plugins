"""

proxenet Interaction Module for Python (PIMP)

Small set of functions for parsing easily http request

"""
import re

__author__ = "@_hugsy_"
__version__ = "0.1"
__license__ = "GPLv2"

CRLF = "\r\n"

class HTTPBadRequestException(Exception):
    pass

class HTTPBadResponseException(Exception):
    pass

class HTTPObject:
    """
    Generic class for manipulating HTTP objects from proxenet
    """
    def __init__(self, **kwargs):
        self.rid        = kwargs.get("rid", 0)
        self.headers	= {}
        self.body	= ""
        return

    def has_header(self, key):
        return key.lower() in self.headers.keys()

    def get_header(self, key):
        return self.headers.get(key.lower(), None)

    def add_header(self, key, value=""):
        self.headers[ key.lower() ] = value
        return

    def del_header(self, key):
        for k in self.headers.keys():
            if k == key.lower():
                self.headers.pop(k, None)
        return

    def update_content_length(self):
        if len(self.body):
            self.add_header("Content-Length", len(self.body))
        return


class HTTPRequest(HTTPObject) :
    """
    Parse a raw HTTP request into Python object.
    This class provides helpers to get and modify the content of an HTTP request
    passed to proxenet.
    """

    def __init__(self, r, **kwargs):
        HTTPObject.__init__(self, **kwargs)
        self.method 	= "GET"
        self.path 	= "/"
        self.version    = "HTTP/1.1"

        try:
            self.parse(r)
        except Exception as e:
            raise HTTPBadRequestException(e)
        return

    def parse(self, req):
        """
        Parse the request by splitting the header and body (if any). The body, method, path and version
        are affected as class attribute, the headers are stored in a dict().
        """
        i = req.find(CRLF*2)
        self.body = req[i+len(CRLF*2):]

        headers = req[:i].split(CRLF)
        parts = re.findall(r"^(?P<method>.+?)\s+(?P<path>.+?)\s+(?P<protocol>.+?)$", headers[0])[0]
        self.method, self.path, self.version = parts

        for header in headers[1:]:
            key, value = re.findall(r"^(?P<key>.+?)\s*:\s*(?P<value>.+?)\s*$", header)[0]
            self.add_header(key, value)
        return

    def __str__(self):
        return "Request {rid} [{method} {path} {version}]".format(rid=self.rid,
                                                                  method=self.method,
                                                                  path=self.path,
                                                                  version=self.version)

    def render(self):
        """
        Reconstruct the HTTP request as raw to be able to yield it to proxenet.
        """
        self.update_content_length()
        head =  "{method} {path} {version}".format(method=self.method, path=self.path, version=self.version)
        hrds = ["{header_name}: {header_value}".format(header_name=k,header_value=v) for k,v in self.headers.iteritems()]

        if len(self.body):   req = CRLF.join([head, ] + hrds + ['', self.body])
        else:                req = CRLF.join([head, ] + hrds + [CRLF, ])
        return req

    @property
    def realpath(self):
        """
        Returns the path of the path attribute.
        """
        i = self.path.rfind("/", 1)
        if i == -1:
            return self.path
        return self.path[:i]

    @property
    def basename(self):
        """
        Returns the name of the script/file/method of the path attribute.
        """
        i = self.path.rfind("/", 1)
        j = self.path.find("?", 1)

        if i==-1 and j==-1:
            return self.path
        elif j==-1:
            return self.path[i+1:]
        elif i==-1:
            return self.path[:j+1]
        else:
            return self.path[i+1:j+1]


class HTTPResponse(HTTPObject):

    def __init__(self, r, **kwargs):
        HTTPObject.__init__(self, **kwargs)
        self.protocol   = "HTTP/1.1"
        self.status     = 200
        self.reason     = "Ok"

        try:
            self.parse(r)
        except Exception as e:
            raise HTTPBadResponseException(e)
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

    def __str__(self):
        return "Response {rid} [{protocol} {status} {reason}]".format(rid=self.rid,
                                                                      protocol=self.protocol,
                                                                      status=self.status,
                                                                      reason=self.reason)

    def render(self):
        self.update_content_length()
        head = "{0} {1} {2}".format(self.protocol, self.status, self.reason)
        hrds = ["{0}: {1}".format(k,v) for k,v in self.headers.iteritems()]

        if len(self.body):    res = CRLF.join([head, ] + hrds + ['', self.body])
        else:                 res = CRLF.join([head, ] + hrds + [CRLF, ])

        return res
