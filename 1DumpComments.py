"""
This script will dump all comments fields from intercepted HTML response.

Note: no deflate/gzip decompression is performed here
"""

__PLUGIN__ = "DumpComments"
__AUTHOR__ = "@_hugsy"

def proxenet_request_hook(rid, request, uri):
    return request

def proxenet_response_hook(rid, response, uri):
    comment_start_tag, comment_end_tag = ("<!--", "-->")
    off = 0
    while True:
        i = response[off:].find(comment_start_tag)
        if i == -1:
            break

        n = response[off+i:].find(comment_end_tag)
        if n==-1:
            off += i + len(comment_start_tag)
            break

        print "Found comment in %d:\n%s" % (rid, response[off+i:off+i+n+3])
        off = off+i+n

    return response
