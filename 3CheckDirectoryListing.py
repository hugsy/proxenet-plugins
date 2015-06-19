"""

proxenet plugin to automatically detect Directory Listing on all the web tree
of a specific URL.

"""

import urllib, urlparse, re


AUTHOR = "hugsy"
PLUGIN_NAME = "CheckDirectoryListing"

ALREADY_VISITED_PATH = []


def success(msg):
    print("\x1b[4m\x1b[1m\x1b[95m" + msg + "\x1b[0m")
    return


def get_paths(uri):
    o = urlparse.urlparse(uri)
    if not hasattr(o, 'path') or len(o.path)==0 or not o.path.startswith("/"):
        return []

    host = "{}://{}".format(o.scheme, o.netloc)
    path = re.sub(r'[]/]{2,}', r'/', o.path)
    urls = []
    prefix = '/'
    for subpath in o.path.split("/"):
        if len(subpath)==0: continue
        prefix += subpath + '/'
        if prefix not in urls:
            urls.append(host + prefix)
    return urls


def scan_dirlist(path):
    PATTERNS = ["Parent Directory", "Last modified", "Index Of",
                "Description", "Name", "Size", "Apache/", "../"]
    match = 0
    success_ratio = 0.70

    try:
        f = urllib.urlopen(path)
        text = f.read()

        for patt in PATTERNS:
            if patt in text:
                match += 1

        ratio = float(match)/len(PATTERNS)

        if (success_ratio/2) < ratio < success_ratio:
            success( "[+] Directory listing on '%s' (LIKELY)" % path )
        elif ratio >= success_ratio:
            success( "[+] Directory listing on '%s'" % path )

    except Exception as e:
        pass

    return


def proxenet_request_hook(request_id, request, uri):
    global ALREADY_VISITED_PATH

    for url in get_paths(uri):
        if url in ALREADY_VISITED_PATH:
            continue

        scan_dirlist(url)
        ALREADY_VISITED_PATH.append( url )

    return request


def proxenet_response_hook(response_id, response, uri):
    return response


if __name__ == "__main__":
    rid = 1337
    target = "192.168.56.102:80"
    path = "/blah/blih//plop//////balhhe?foobar"
    uri = "http://{:s}{:s}".format(target, path)
    req = "GET {:s} HTTP/1.1\r\n".format(path)
    req+= "Host: {:s}\r\n".format(target)
    req+= "X-Header: Powered by proxenet\r\n\r\n"

    proxenet_request_hook(rid, req, uri)
    exit(0)
