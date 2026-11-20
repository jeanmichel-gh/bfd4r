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

require 'bfd/version'
require 'bfd/logging'
require 'bfd/daemon/config'
require 'bfd/daemon/runner'
require 'bfd/daemon/udp'
require 'bfd/daemon/api'

module BFD
  module Daemon
    # The bfdd4r program: binds its API socket first, so a second bfdd4r
    # in the namespace stops before touching anything; then the UDP
    # transport, the Runner, the file's sessions and the API; and runs
    # until INT or TERM.
    class Server
      USAGE = <<~TEXT
        Usage: bfdd4r [-f FILE] [-s NAME] [--log FILE] [-d] [-v] [-h]

          -f, --file FILE     sessions and settings (bfd/daemon/config.rb)
          -s, --socket NAME   the API socket (default: the file's, else $BFD4R_SOCKET,
                              else @bfdd4r; @ is the abstract namespace)
              --log FILE      where to log; - is standard output, the default
          -d, --debug         log at debug
          -v, --version       the version
          -h, --help          this help

        One bfdd4r per network namespace: a second one finds the socket in
        use and exits at once, with status 0.
      TEXT

      # The client name of sessions from the file.
      FILE_CLIENT = 'file'

      def initialize(out = $stdout, err = $stderr)
        @out = out
        @err = err
      end

      # Runs until a signal, or until stop is pushed on the queue a test
      # gives; answers the exit status. port: the UDP port, which a test
      # may change.
      def start(argv, env = ENV, stop: nil, port: Udp::PORT)
        opts = parse(argv)
        return usage(0) if opts[:help]
        if opts[:version]
          @out.puts BFD::VERSION
          return 0
        end
        return usage(1) if opts[:error]

        config = opts[:file] ? Config.load(opts[:file]) : Config.new
        name = opts[:socket] || (opts[:file] && config.socket) || env['BFD4R_SOCKET']
        path = Config.socket_path(name.nil? || name.empty? ? Config::DEFAULT_SOCKET : name)
        logger = Logging.to_io(opts[:log] || '-', level: opts[:debug] ? :debug : :info)
        api = Api.new(nil, path: path, logger: logger)
        begin
          api.start
        rescue Api::InUse => e
          @err.puts "bfdd4r: #{e.message}; this one exits"
          return 0
        end
        udp = Udp.new(port: port, logger: logger)
        runner = Runner.new(transport: udp, floor: config.floor)
        udp.on_packet = ->(octets, **k) { runner.push_packet(octets, **k) }
        api.runner = runner
        runner.start
        logs = log_events(runner.core.events, logger)
        config.sessions.each { |s| runner.on_loop { |c| c.add(client: FILE_CLIENT, **s) } }
        logger.call(:info, "bfdd4r #{BFD::VERSION} answers on #{api.shown_path}, #{config.sessions.size} session(s) from the file")
        if config.floor < Core::FLOOR
          logger.call(:warn, "floor lowered to #{config.floor} microseconds; under #{Core::FLOOR} sessions may flap when busy")
        end
        stop ? stop.pop : wait_for_signals
        logger.call(:info, 'bfdd4r stopping')
        0
      rescue Config::Error, SystemCallError, ArgumentError => e
        @err.puts "bfdd4r: #{e.message}"
        1
      ensure
        logs&.kill
        api&.stop
        runner&.stop
        udp&.close
      end

      private

      # Every event, as a log line, from a thread of its own.
      def log_events(events, logger)
        sub = events.subscribe
        Thread.new do
          loop do
            sub.take(1.0).each { |e| logger.call(e.level, "#{e.kind}: #{e.message}") }
          end
        end
      end

      def wait_for_signals
        r, w = IO.pipe
        %w[INT TERM].each do |sig|
          Signal.trap(sig) do
            w.write_nonblock('x')
          rescue IOError, SystemCallError
            nil
          end
        end
        r.read(1)
      end

      def usage(status)
        (status.zero? ? @out : @err).print USAGE
        status
      end

      def parse(argv)
        opts = {}
        i = 0
        while i < argv.size
          case argv[i]
          when '-f', '--file' then opts[:file] = value(argv, i += 1, opts)
          when '-s', '--socket' then opts[:socket] = value(argv, i += 1, opts)
          when '--log' then opts[:log] = value(argv, i += 1, opts)
          when '-d', '--debug' then opts[:debug] = true
          when '-v', '--version' then opts[:version] = true
          when '-h', '--help' then opts[:help] = true
          else opts[:error] = true
          end
          i += 1
        end
        opts
      end

      def value(argv, i, opts)
        argv[i] || (opts[:error] = true) && nil
      end
    end
  end
end
