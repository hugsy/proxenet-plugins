"""
This plugin for proxenet will strip any HTTPS pattern
in responses and automatically replace it with their
HTTP equivalent.
"""

AUTHOR = "hugsy"
PLUGIN_NAME = "HttpsStrip"


def proxenet_request_hook(request_id, request, uri):
    return request

def proxenet_response_hook(response_id, response, uri):
    return response.replace("https://", " http://")

if __name__ == "__main__":
    pass
