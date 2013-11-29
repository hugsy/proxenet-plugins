import requests
    
def scan_dirlist(path):
    try:
        h = requests.get(path, verify=False)
        if h.status_code == 200:
            if "Parent Directory" in h.text and "Index Of" in h.text:
                print "[+] Directory listing on '%s'" % path
    except:
        pass
    
    return


def proxenet_request_hook(request_id, request, uri):
    try:
        i = uri.find("/", uri.find("://") + 3)
        
        while True:
            j = uri.find("/", i+1)
            if j < 0:
                break
            
            path = uri[:j]
            scan_dirlist(path)
            i = j
            
    except:
        pass
    
    return request

    
def proxenet_response_hook(response_id, response, uri):
    return response


if __name__ == "__main__":
    # test 
    req = "GET /sqlinjection/example1/?username=test&password=test&submit=Submit HTTP/1.1\r\nHost: 192.168.2.6\r\n\r\n"
    proxenet_request_hook(1337,
                          req,
                          "http://192.168.2.6/sqlinjection/example1/foo/a/?username=test&password=test&submit=Submit")
