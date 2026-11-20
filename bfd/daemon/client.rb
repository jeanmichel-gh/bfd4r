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
require 'bfd/daemon/config'

module BFD
  module Daemon
    # The other half of bfdd4r's socket: one request line, one reply
    # line. Adapted from vtep4r's vxlan/daemon/client.rb. isisd, ospfd and
    # bgp4rd copy it, or a smaller one, to ask for sessions (step 6).
    class Client
      class Error < StandardError; end

      # $BFD4R_SOCKET, else the abstract "@bfdd4r". "@name" is abstract.
      def self.default_socket(env = ENV)
        name = env['BFD4R_SOCKET']
        name = Config::DEFAULT_SOCKET if name.nil? || name.empty?
        Config.socket_path(name)
      end

      attr_reader :path

      def initialize(path = nil, env = ENV)
        @path = path ? Config.socket_path(path) : Client.default_socket(env)
        @id = 0
      end

      def shown_path
        @path.start_with?("\0") ? "@#{@path[1..]}" : @path
      end

      # One method's result, or Error with bfdd4r's own message.
      def call(method, params = {})
        @sock ||= UNIXSocket.new(@path)
        @id += 1
        @sock.write("#{JSON.generate(id: @id, method: method, params: params)}\n")
        line = @sock.gets or raise Error, 'bfdd4r closed the connection'
        reply = JSON.parse(line)
        raise Error, reply['error'] if reply['error']

        reply['result']
      rescue Errno::ENOENT, Errno::ECONNREFUSED
        raise Error, "no bfdd4r answers on #{shown_path}"
      rescue Errno::EACCES
        raise Error, "no permission on #{shown_path}"
      rescue Errno::EPIPE, Errno::ECONNRESET, IOError
        @sock = nil
        raise Error, 'lost the connection to bfdd4r'
      rescue JSON::ParserError => e
        raise Error, "bfdd4r answered something that is not JSON: #{e.message[0, 120]}"
      end

      # A streaming method: yields every line, parsed, the result first.
      # Return false from the block to stop, which sends
      # events.unsubscribe.
      def stream(method, params = {})
        @sock ||= UNIXSocket.new(@path)
        @id += 1
        @sock.write("#{JSON.generate(id: @id, method: method, params: params)}\n")
        while (line = @sock.gets)
          break if yield(JSON.parse(line)) == false
        end
        unsubscribe
      rescue Errno::ENOENT, Errno::ECONNREFUSED
        raise Error, "no bfdd4r answers on #{shown_path}"
      rescue Errno::EPIPE, Errno::ECONNRESET, IOError
        @sock = nil
        raise Error, 'lost the connection to bfdd4r'
      end

      def unsubscribe
        return nil unless @sock && !@sock.closed?

        @id += 1
        @sock.write("#{JSON.generate(id: @id, method: 'events.unsubscribe', params: {})}\n")
        while (line = @sock.gets)
          break if JSON.parse(line)['id'] == @id
        end
        nil
      rescue Errno::EPIPE, Errno::ECONNRESET, IOError
        @sock = nil
      end

      def close
        @sock&.close
        @sock = nil
      end
    end
  end
end
