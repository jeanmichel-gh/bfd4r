#--
# Copyright 2026 Jean-Michel Esnault.
# All rights reserved.
# See LICENSE.txt for permissions.
#
#
# This file is part of BFD4R.
#
# BFD4R is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# BFD4R is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with BFD4R.  If not, see <http://www.gnu.org/licenses/>.
#++

require 'json'
require 'bfd/version'
require 'bfd/daemon/client'

module BFD
  module Daemon
    # bfd4r-cli: one API method, its result printed as JSON. Adapted from
    # vtep4r's vtep4r-cli.
    class CLI
      USAGE = <<~TEXT
        Usage: bfd4r-cli [options] METHOD [JSON | KEY=VALUE...]

          bfd4r-cli api.info                       the version, methods and event kinds
          bfd4r-cli show.sessions                  every session, its RFC 5880 variables and counts
          bfd4r-cli show.counters                  packets that found no session
          bfd4r-cli session.add interface=eth1 peer=10.0.0.2 local=10.0.0.1 client=me
          bfd4r-cli session.set interface=eth1 peer=10.0.0.2 desired_min_tx=1000000
          bfd4r-cli session.admin interface=eth1 peer=10.0.0.2 down=true
          bfd4r-cli session.delete interface=eth1 peer=10.0.0.2 client=me
          bfd4r-cli events.subscribe kinds=session  a stream, one line per event

        Options:
          -s, --socket NAME   bfdd4r's socket (default: $BFD4R_SOCKET, else @bfdd4r;
                              @ is the abstract namespace)
              --pretty        indent the JSON
          -v, --version       the version
          -h, --help          this help
      TEXT

      def initialize(out = $stdout, err = $stderr, client = nil)
        @out = out
        @err = err
        @client = client
      end

      def start(argv, env = ENV)
        opts = parse(argv)
        return help(0) if opts[:help]
        if opts[:version]
          @out.puts BFD::VERSION
          return 0
        end
        return help(1) if opts[:error] || opts[:method].nil?

        params = CLI.params(opts[:args])
        client = @client || Client.new(opts[:socket], env)
        return subscribe(client, params) if opts[:method] == 'events.subscribe'

        result = client.call(opts[:method], params)
        @out.puts(opts[:pretty] ? JSON.pretty_generate(result) : JSON.generate(result))
        0
      rescue Client::Error, ArgumentError, JSON::ParserError => e
        @err.puts "bfd4r-cli: #{e.message}"
        1
      ensure
        client&.close
      end

      # A JSON object, or KEY=VALUE words. Digits are a number, true and
      # false are booleans, and [ or { starts JSON, so a list can be given.
      def self.params(words)
        return {} if words.empty?

        if words[0].start_with?('{')
          h = JSON.parse(words.join(' '))
          raise ArgumentError, 'the parameters are a JSON object' unless h.is_a?(Hash)

          return h
        end
        words.to_h do |w|
          k, v = w.split('=', 2)
          raise ArgumentError, "#{w.inspect} is not KEY=VALUE" if v.nil? || k.empty?

          value = if v.match?(/\A\d+\z/) then Integer(v)
                  elsif %w[true false].include?(v) then v == 'true'
                  elsif v.start_with?('[', '{') then JSON.parse(v)
                  else v
                  end
          [k, value]
        end
      end

      private

      def subscribe(client, params)
        client.stream('events.subscribe', params) do |line|
          raise Client::Error, line['error'] if line['error'] && line.key?('id') && !line.key?('result')

          @out.puts(JSON.generate(line))
        end
        0
      rescue Interrupt
        client.unsubscribe
        0
      end

      def help(status)
        (status.zero? ? @out : @err).print USAGE
        status
      end

      def parse(argv)
        opts = { args: [] }
        i = 0
        while i < argv.size
          case argv[i]
          when '-h', '--help' then opts[:help] = true
          when '-v', '--version' then opts[:version] = true
          when '-s', '--socket'
            opts[:socket] = argv[i += 1]
            opts[:error] = true unless opts[:socket]
          when '--pretty' then opts[:pretty] = true
          else opts[:method] ? opts[:args] << argv[i] : opts[:method] = argv[i]
          end
          i += 1
        end
        opts
      end
    end
  end
end
