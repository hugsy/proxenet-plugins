"""
Dump to stdout HTTP requests and responses only if their content
is text-only (no raw bytes)
"""

__PLUGIN_NAME__ = "DumpReqRes"
__PLUGIN_AUTHOR__ = "@hugsy"


def proxenet_request_hook(rid, request, uri):
    c = set([ chr(i) for i in range(0, 20) ]) - set(['\r', '\n'])
    r = set(request)
    if len(c & r)==0:
        print rid, "->", uri
        print request
    return request


def proxenet_response_hook(rid, response, uri):
    c = set([ chr(i) for i in range(0, 20) ]) - set(['\r', '\n'])
    r = set(response)
    if len(c & r)==0:
        print rid, "->", uri
        print response
    return response
