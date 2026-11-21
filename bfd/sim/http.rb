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
require 'socket'
require 'io/wait'
require 'bfd/version'
require 'bfd/sim/injector'

module BFD
  module Sim
    # bfd4r-sim's HTTP API, after bgp4r-sim's and vtep4r-sim's, so
    # routescope's driver is a copy of its Bgp4rSim with the paths
    # changed: HTTP on 127.0.0.1:8080, GET for reads, POST for actions,
    # and a header on every POST. Every call runs on the injector's loop.
    #
    # **It binds the loopback by default.** A lab reaches it with docker
    # exec; an injector any container on the segment could drive would
    # leave a scenario's record of what happened incomplete.
    #
    # **A POST carries X-BFD4R: routescope**, so a page of another site
    # cannot send faults into a lab. **The header name is matched case
    # insensitively**: Net::HTTP capitalises it per word, so X-BFD4R
    # arrives as X-Bfd4r.
    #
    # **No web framework and no webrick**, which left the standard
    # library: HTTP/1.1 over TCPServer, one connection at a time, no
    # keep-alive, no chunked body, no TLS, no authentication beyond the
    # header.
    #
    # A refused action answers 400 for a request the caller can fix and
    # 409 for a state that refuses it now, a peer session already running;
    # both with {"error": "..."}.
    class Http
      MAX_HEAD = 8 << 10
      MAX_BODY = 1 << 20
      IDLE = 60
      VERSION = 1
      HEADER = 'x-bfd4r'
      HEADER_VALUE = 'routescope'

      READS = { '/api/status' => :status, '/api/sent' => :sent, '/api/received' => :received,
                '/api/catalog' => :catalog, '/api/events' => :events_since }.freeze
      ACTIONS = { '/api/send' => 'send', '/api/fault' => 'fault', '/api/peer' => 'peer',
                  '/api/behave' => 'behave', '/api/stop' => 'stop' }.freeze
      REASONS = { 200 => 'OK', 400 => 'Bad Request', 403 => 'Forbidden', 404 => 'Not Found',
                  405 => 'Method Not Allowed', 409 => 'Conflict', 413 => 'Payload Too Large',
                  500 => 'Internal Server Error' }.freeze
      DEFAULT_BIND = '127.0.0.1'
      DEFAULT_PORT = 8080

      attr_reader :bind, :injector

      # HOST:PORT, [IPV6]:PORT or PORT.
      def self.address(text)
        s = text.to_s.strip
        case s
        when /\A\[(.+)\]:(\d+)\z/ then { bind: Regexp.last_match(1), port: Integer(Regexp.last_match(2)) }
        when /\A([^:]*):(\d+)\z/
          { bind: Regexp.last_match(1).empty? ? DEFAULT_BIND : Regexp.last_match(1), port: Integer(Regexp.last_match(2)) }
        when /\A\d+\z/ then { bind: DEFAULT_BIND, port: Integer(s) }
        else raise ArgumentError, "api #{text.inspect}: write it as HOST:PORT, [IPV6]:PORT or PORT"
        end
      end

      # on_loop: runs a block on the injector's thread (Runtime::Loop);
      # inline unless given.
      def initialize(injector, bind: DEFAULT_BIND, port: DEFAULT_PORT, logger: nil, on_loop: nil)
        @injector = injector
        @on_loop = on_loop || ->(&b) { b.call }
        @bind = bind
        @port = port
        @logger = logger
      end

      def port
        @server ? @server.addr[1] : @port
      end

      def start
        @server = TCPServer.new(@bind, @port)
        @thread = Thread.new { accept_loop }
        self
      end

      def stop
        @server.close if @server && !@server.closed?
        @thread&.join(2)
        self
      end

      # [status, answer] for one request; headers' names are lower case.
      def handle(method, path, headers = {}, body = '')
        dispatch(method, path, headers, body)
      rescue Busy => e
        [409, { error: e.message }]
      rescue Refused, ArgumentError, KeyError, TypeError => e
        [400, { error: e.message }]
      rescue StandardError => e
        log(:error, "api #{method} #{path}: #{e.class}: #{e.message}")
        [500, { error: "internal error: #{e.class}" }]
      end

      def index
        [200, { bfd4r: BFD::VERSION, api: VERSION, reads: READS.keys.sort, actions: ACTIONS.sort.to_h,
                post_header: "#{HEADER.upcase}: #{HEADER_VALUE}" }]
      end

      private

      def dispatch(method, path, headers, body)
        route, query = path.to_s.split('?', 2)
        return index if ['/', '/api'].include?(route)

        if READS.key?(route)
          return [405, { error: "#{route} is a GET" }] unless method == 'GET'

          read = READS[route]
          q = params(query)
          return [200, run { read == :events_since ? @injector.events_since(q) : @injector.public_send(read) }]
        end
        action = ACTIONS[route]
        return not_found(route) unless action
        return [405, { error: "#{route} is a POST" }] unless method == 'POST'
        return [403, { error: "a POST needs #{HEADER.upcase}: #{HEADER_VALUE}" }] unless headers[HEADER].to_s == HEADER_VALUE

        b = parse_body(body)
        [200, run { @injector.act(action, b) }]
      end

      def not_found(route)
        [404, { error: "no such path #{route}; this injector answers #{(READS.keys + ACTIONS.keys).sort.join(', ')}" }]
      end

      def parse_body(body)
        text = body.to_s.strip
        return {} if text.empty?

        parsed = JSON.parse(text)
        raise Refused, "a request body is a JSON object, got #{parsed.class}" unless parsed.is_a?(Hash)

        parsed
      rescue JSON::ParserError => e
        raise Refused, "bad JSON: #{e.message[0, 120]}"
      end

      def params(query)
        return {} if query.nil? || query.empty?

        query.split('&').each_with_object({}) do |pair, h|
          k, v = pair.split('=', 2)
          h[unescape(k)] = unescape(v.to_s) unless k.nil? || k.empty?
        end
      end

      def unescape(s)
        s.tr('+', ' ').gsub(/%(\h\h)/) { Regexp.last_match(1).hex.chr }
      end

      def run(&block)
        @on_loop.call(&block)
      end

      def log(level, message)
        @logger&.call(level, message)
      end

      def accept_loop
        loop do
          client = @server.accept
          begin
            serve(client)
          rescue StandardError => e
            log(:error, "api: #{e.class}: #{e.message}")
          ensure
            client.close unless client.closed?
          end
        end
      rescue IOError, Errno::EBADF
        nil # the listening socket was closed by stop
      end

      def serve(sock)
        return unless sock.wait_readable(IDLE)

        head = read_head(sock) or return
        method, path, headers = head
        len = headers['content-length'].to_i
        status, answer = if len > MAX_BODY then [413, { error: "a request body over #{MAX_BODY} octets" }]
                         else handle(method, path, headers, len.positive? ? sock.read(len).to_s : '')
                         end
        respond(sock, status, answer)
      rescue Errno::ECONNRESET, Errno::EPIPE, IOError, EOFError
        nil
      end

      def read_head(sock)
        lines = []
        size = 0
        while (line = sock.gets("\n"))
          size += line.bytesize
          return respond(sock, 413, error: "request headers over #{MAX_HEAD} octets") && nil if size > MAX_HEAD

          text = line.chomp
          break if text.empty?

          lines << text
        end
        return nil if lines.empty?

        method, path, = lines.first.split(' ')
        return respond(sock, 400, error: 'not an HTTP request line') && nil if method.nil? || path.nil?

        headers = lines.drop(1).each_with_object({}) do |l, h|
          name, value = l.split(':', 2)
          h[name.to_s.strip.downcase] = value.to_s.strip unless value.nil?
        end
        [method.upcase, path, headers]
      end

      def respond(sock, status, answer)
        body = JSON.generate(answer)
        sock.write("HTTP/1.1 #{status} #{REASONS.fetch(status, 'OK')}\r\nContent-Type: application/json\r\n" \
                   "Content-Length: #{body.bytesize + 1}\r\nConnection: close\r\n\r\n#{body}\n")
        true
      rescue Errno::EPIPE, Errno::ECONNRESET, IOError
        true
      end
    end
  end
end
