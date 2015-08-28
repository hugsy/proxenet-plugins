turf_libdir = File.expand_path( File.dirname(__FILE__) )
$LOAD_PATH.unshift(turf_libdir) unless $LOAD_PATH.include?(turf_libdir)
require 'turf/turf'
require 'uri'


module SeriouslyNoHardFeelings
  $AUTHOR = "hugsy"
  $PLUGIN_NAME = "NoHardFeelingsBro"

  $banner = "  _               __
 | |             / _|
 | |_ _   _ _ __| |_
 | __| | | | '__|  _|
 | |_| |_| | |  | |
  \\__|\\__,_|_|  |_|

"
  $show_banner = true
  module_function

  def interact_request(rid, req, uri)
    if $show_banner
      puts $banner
      $show_banner = false
    end
    puts "Your request RID=#{rid} ('#{uri}') is in variable `http'"
    puts "To send the modified request, enter 'quit'; to send the original request, enter 'reset'."

    is_ssl = uri.start_with? "https://"
    url = URI(uri)
    print
    http = Turf::Request.new req, hostname: url.host, port: url.port, use_ssl: is_ssl
    while true do
      print "\x1b[4m" << "\x1b[1m" << ">>>" << "\x1b[0m" << " "
      cmd = gets()
      if cmd == "reset\n" then
        ret = req
        break
      elsif cmd == "quit\n" then
        ret = http.to_s
        break
      else
        eval(cmd)
      end
    end

    return ret
  end

  def proxenet_request_hook(request_id, request, uri)
    ret = interact_request( request_id, request, uri )
    return ret
  end

  def proxenet_response_hook(response_id, response, uri)
    return response
  end

end

if __FILE__ == $0
    # use for test cases
end
