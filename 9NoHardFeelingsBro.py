import burst.http
import burst.console

AUTHOR = "hugsy"
PLUGIN_NAME = "NoHardFeelingsBro"

show_banner = True

def interact_request(rid, req, uri):
    global show_banner
    if show_banner:
        print "Loading..."
        print burst.console.banner
        show_banner = False
    print "Your request RID={:d} ('{:s}') is in variable `http'".format(rid, uri)
    print "To send the modified request, enter 'quit';",
    print "to send the original request, enter 'reset'."

    is_ssl = uri.startswith("https://")
    http = burst.http.Request(req, use_ssl=is_ssl)
    while True:
        try:
            cmd = raw_input("\x1b[4m"+"\x1b[1m"+">>>"+"\x1b[0m"+" ").strip()
            if cmd == "reset":
                ret = req
                break
            if cmd == "quit":
                ret = str(http)
                break
            exec(cmd)
        except KeyboardInterrupt:
            ret = req
            break
    return ret

def proxenet_request_hook(request_id, request, uri):
    return interact_request( request_id, request, uri )

def proxenet_response_hook(response_id, response, uri):
    return response

if __name__ == "__main__":
    burst.console.interact()
