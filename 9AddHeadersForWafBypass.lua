AUTHOR = "hugsy"
PLUGIN_NAME = "AddHeadersForWafBypass"

function proxenet_on_load()
end

function proxenet_on_leave()
end

function proxenet_request_hook (request_id, request, uri)
   local CRLF = "\r\n"
   local header = "X-Originating-IP: 127.0.0.1" .. CRLF
   header = header .. "X-Forwarded-For: 127.0.0.1" .. CRLF
   header = header .. "X-Remote-IP: 127.0.0.1" .. CRLF
   header = header .. "X-Remote-Addr: 127.0.0.1"

   return string.gsub(request,
                      CRLF .. CRLF,
                      CRLF .. header .. CRLF..CRLF)
end

function proxenet_response_hook (response_id, response, uri)
   return response
end
