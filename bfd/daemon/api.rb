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
require 'bfd/daemon/config'

module BFD
  module Daemon
    # bfdd4r's control API: one JSON object per line over a Unix socket,
    # in each direction, as bgp4rd's, isisd's and vtep4rd's, so routescope
    # and the routers read it with the same one-line client:
    #
    #   -> {"id":1,"method":"session.add","params":{"interface":"eth1",...}}
    #   <- {"id":1,"result":{...}}
    #   <- {"id":1,"error":"unknown method \"show.foo\"; this bfdd4r answers ..."}
    #
    # The socket is abstract by default, "\0bfdd4r", one per network
    # namespace: a second bfdd4r in the namespace cannot bind it (InUse).
    #
    # Adapted from vtep4r's vxlan/daemon/api.rb. **A bad request must not
    # take the daemon down**: a line that is not JSON, JSON that is not an
    # object, a line longer than MAX_LINE, a method that raises and a
    # client that goes away are each answered or ignored, one connection
    # at a time. Every method runs on the Runner's loop.
    #
    # events.subscribe turns the connection into a stream, in bgp4rd's form:
    #
    #   -> {"id":2,"method":"events.subscribe","params":{"kinds":["session"],"since":120}}
    #   <- {"id":2,"result":{"seq":131,"replayed":11,"kinds":["session"]}}
    #   <- {"event":{"seq":121,"time":"...","level":"warn","kind":"session",...}}
    #   <- {"keepalive":"2026-11-20T21:20:15.004Z","seq":131}
    #   -> {"id":3,"method":"events.unsubscribe"}
    #   <- {"id":3,"result":{"unsubscribed":true}}
    class Api
      MAX_LINE = 1 << 20
      MAX_CLIENTS = 32
      IDLE = 900
      KEEPALIVE = 15
      VERSION = 1

      METHODS = {
        'api.info' => ->(a, _p) { a.info },
        'session.add' => ->(a, p) { a.add(p) },
        'session.delete' => ->(a, p) { a.delete(p) },
        'session.admin' => ->(a, p) { a.admin(p) },
        'session.set' => ->(a, p) { a.set(p) },
        'show.sessions' => ->(a, p) { a.sessions(p) },
        'show.counters' => ->(a, _p) { a.counters }
      }.freeze
      STREAM_METHODS = %w[events.subscribe events.unsubscribe].freeze

      class InUse < StandardError; end

      def self.names
        (METHODS.keys + STREAM_METHODS).sort
      end

      attr_reader :path
      # The Runner, which bfdd4r sets once the socket is bound.
      attr_accessor :runner

      # path: the socket, "\0name" for an abstract one.
      def initialize(runner, path:, logger: nil, keepalive: KEEPALIVE)
        @runner = runner
        @path = path
        @logger = logger
        @keepalive = keepalive
        @clients = []
        @lock = Mutex.new
      end

      def shown_path
        @path.start_with?("\0") ? "@#{@path[1..]}" : @path
      end

      def start
        @server = begin
          UNIXServer.new(@path)
        rescue Errno::EADDRINUSE
          raise InUse, "another bfdd4r answers on #{shown_path}"
        end
        @thread = Thread.new { accept_loop }
        self
      end

      def stop
        @server.close if @server && !@server.closed?
        @thread&.join(2)
        @lock.synchronize { @clients.dup }.each { |c| c.close unless c.closed? }
        File.delete(@path) if !@path.start_with?("\0") && File.socket?(@path)
        self
      end

      def handle(req)
        id = req['id']
        name = req['method'].to_s
        fn = METHODS[name] || (STREAM_METHODS.include?(name) && :stream)
        return { id: id, error: "unknown method #{name.inspect}; this bfdd4r answers #{Api.names.join(', ')}" } unless fn

        params = req['params'].is_a?(Hash) ? req['params'] : {}
        return { id: id, error: 'events.subscribe is a stream: send it on the socket' } if name == 'events.subscribe'
        return { id: id, result: { unsubscribed: false } } if name == 'events.unsubscribe'

        { id: id, result: fn.call(self, params) }
      rescue ArgumentError, KeyError, Config::Error => e
        { id: id, error: e.message }
      rescue StandardError => e
        log(:error, "api #{name}: #{e.class}: #{e.message}")
        { id: id, error: "internal error: #{e.class}" }
      end

      # The methods' bodies, public so METHODS can reach them.

      # The version, the methods and the event kinds, for routescope's
      # contract (routescope docs/design/api-contract.md).
      def info
        { version: BFD::VERSION, api: VERSION, methods: Api.names, event_kinds: Events::KINDS.map(&:to_s),
          event_seq: @runner.core.events.seq }
      end

      def add(p)
        client = p.fetch('client').to_s
        s = Config.session(p.reject { |k, _| k == 'client' })
        row(@runner.on_loop { |c| c.add(client: client, **s) })
      end

      def delete(p)
        e = @runner.on_loop { |c| c.delete(**key(p), client: p.fetch('client').to_s) }
        { interface: e.interface, peer: e.peer, clients: e.clients, state: e.session.session_state }
      end

      def admin(p)
        down = p.fetch('down')
        raise ArgumentError, 'down is true or false' unless [true, false].include?(down)

        row(@runner.on_loop { |c| c.admin(**key(p), down: down) })
      end

      def set(p)
        timers = p.reject { |k, _| %w[interface peer].include?(k) }
        unknown = timers.keys - %w[desired_min_tx required_min_rx detect_mult]
        raise ArgumentError, "unknown timer #{unknown.join(', ')}" unless unknown.empty?

        timers = timers.to_h { |k, v| [k.to_sym, Integer(v)] }
        row(@runner.on_loop { |c| c.set(**key(p), **timers) })
      end

      # Every session, or one: interface and peer.
      def sessions(p)
        @runner.on_loop do |c|
          rows = c.show
          rows = rows.select { |r| r[:interface] == p['interface'] && r[:peer] == p['peer'] } if p['peer']
          rows
        end
      end

      def counters
        @runner.on_loop { |c| { sessions: c.entries.size, no_session: c.counters[:no_session].to_h } }
      end

      private

      def key(p)
        { interface: p.fetch('interface').to_s, peer: p.fetch('peer').to_s }
      end

      def row(entry)
        @runner.on_loop do |c|
          c.show.find { |r| r[:interface] == entry.interface && r[:peer] == entry.peer }
        end
      end

      def log(level, message)
        @logger&.call(level, message)
      end

      def accept_loop
        loop do
          client = @server.accept
          busy = @lock.synchronize { @clients.size >= MAX_CLIENTS ? true : (@clients << client && false) }
          if busy
            write(client, error: "too many connections (#{MAX_CLIENTS})")
            client.close
            next
          end
          Thread.new(client) do |c|
            serve(c)
          ensure
            @lock.synchronize { @clients.delete(c) }
            c.close unless c.closed?
          end
        end
      rescue IOError, Errno::EBADF
        nil
      end

      def serve(sock)
        while sock.wait_readable(IDLE)
          req = read_request(sock)
          next if req == :skip
          break if req.nil?

          if req['method'] == 'events.subscribe'
            stream(sock, req) or break
          else
            write(sock, handle(req))
          end
        end
      rescue IOError, SystemCallError
        nil
      end

      def read_request(sock)
        line = sock.gets(MAX_LINE) or return nil
        unless line.end_with?("\n") || line.bytesize < MAX_LINE
          write(sock, error: "request longer than #{MAX_LINE} octets")
          return nil
        end
        req = JSON.parse(line)
        return req if req.is_a?(Hash)

        write(sock, error: 'a request is a JSON object')
        :skip
      rescue JSON::ParserError => e
        write(sock, error: "bad JSON: #{e.message[0, 120]}")
        :skip
      end

      def stream(sock, req)
        events = @runner.core.events
        params = req['params'].is_a?(Hash) ? req['params'] : {}
        sub = begin
          events.subscribe(kinds: params['kinds'] && Array(params['kinds']), since: params['since'])
        rescue ArgumentError, TypeError => e
          write(sock, id: req['id'], error: e.message)
          return true
        end
        write(sock, id: req['id'], result: { seq: events.seq, replayed: sub.replayed, kinds: sub.kinds&.map(&:to_s) })
        clock = @runner.clock
        quiet_since = clock.now
        loop do
          if sock.wait_readable(0)
            r = read_request(sock)
            return false if r.nil?
            next if r == :skip

            if r['method'] == 'events.unsubscribe'
              events.unsubscribe(sub)
              sub = nil
              write(sock, id: r['id'], result: { unsubscribed: true })
              return true
            end
            write(sock, id: r['id'], error: "#{r['method']} refused: this connection is streaming events; " \
                                            'send events.unsubscribe, or use another connection')
          end
          taken = sub.take(0.2)
          taken.each { |e| write(sock, event: e.to_h) }
          quiet_since = clock.now unless taken.empty?
          next unless clock.now - quiet_since >= @keepalive

          write(sock, keepalive: clock.wall.utc.strftime('%Y-%m-%dT%H:%M:%S.%LZ'), seq: events.seq)
          quiet_since = clock.now
        end
      ensure
        events.unsubscribe(sub) if sub
      end

      def write(sock, obj)
        sock.write("#{JSON.generate(obj)}\n")
      rescue IOError, SystemCallError
        nil
      end
    end
  end
end
