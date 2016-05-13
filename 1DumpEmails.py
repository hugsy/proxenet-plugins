"""
This script will dump all emails in intercepted HTML response.

Note: no deflate/gzip decompression is performed here
"""

__PLUGIN__ = "DumpEmails"
__AUTHOR__ = "@_hugsy_"

import re

def proxenet_request_hook(rid, request, uri):
    return request

def proxenet_response_hook(rid, response, uri):
    patt = re.compile(r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)")
    for email in patt.findall(response):
        print "Found email in %d: %s" % (rid, email)

    return response
