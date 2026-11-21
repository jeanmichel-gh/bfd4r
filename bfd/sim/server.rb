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
require 'bfd/runtime/loop'
require 'bfd/daemon/udp'
require 'bfd/sim/config'
require 'bfd/sim/injector'
require 'bfd/sim/http'

module BFD
  module Sim
    # The bfd4r-sim program: reads its file, starts the injector on its
    # loop, the UDP transport and the HTTP API, and runs until INT or
    # TERM. Port 3784 is bound only when a peer session starts.
    class Server
      USAGE = <<~TEXT
        Usage: bfd4r-sim -f FILE [--api HOST:PORT] [--log FILE] [-d] [-v] [-h]

          -f, --file FILE     the configuration: local, interface, api
              --api ADDR      the HTTP API, HOST:PORT or PORT (default 127.0.0.1:8080)
              --log FILE      where to log; - is standard output, the default
          -d, --debug         log at debug
          -v, --version       the version
          -h, --help          this help
      TEXT

      def initialize(out = $stdout, err = $stderr)
        @out = out
        @err = err
      end

      # Runs until a signal, or until stop is pushed on the queue a test
      # gives; answers the exit status. on_start: called with the HTTP
      # API once it listens, for a test to learn its port.
      def start(argv, stop: nil, port: Daemon::Udp::PORT, on_start: nil)
        opts = parse(argv)
        return usage(0) if opts[:help]
        if opts[:version]
          @out.puts BFD::VERSION
          return 0
        end
        return usage(1) if opts[:error] || opts[:file].nil?

        config = Config.load(opts[:file])
        addr = Http.address(opts[:api] || config.api)
        logger = Logging.to_io(opts[:log] || '-', level: opts[:debug] ? :debug : :info)
        udp = Daemon::Udp.new(port: port, logger: logger, listen: false)
        injector = nil
        runner = Runtime::Loop.new { |octets, **meta| injector.receive(octets, **meta) }
        injector = Injector.new(transport: udp, scheduler: runner.scheduler, local: config.local,
                                interface: config.interface)
        udp.on_packet = ->(octets, **meta) { runner.push_packet(octets, **meta) }
        runner.start
        http = Http.new(injector, bind: addr[:bind], port: addr[:port], logger: logger,
                                  on_loop: ->(&b) { runner.on_loop(&b) }).start
        logger.call(:info, "bfd4r-sim #{BFD::VERSION} #{config.local}: API on http://#{addr[:bind]}:#{http.port}")
        on_start&.call(http)
        stop ? stop.pop : wait_for_signal
        logger.call(:info, 'bfd4r-sim stopping')
        runner.on_loop { injector.act('stop', {}) }
        0
      rescue Config::Error, ArgumentError, SystemCallError => e
        @err.puts "bfd4r-sim: #{e.message}"
        1
      ensure
        http&.stop
        runner&.stop
        udp&.close
      end

      private

      def wait_for_signal
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
          when '--api' then opts[:api] = value(argv, i += 1, opts)
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
