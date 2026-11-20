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

require 'yaml'
require 'bfd/daemon/core'

module BFD
  module Daemon
    # bfdd4r's file, read and checked. Unknown keys are refused by name,
    # as bgp4rd and vtep4rd refuse them, so a typo is an error and not a
    # default (routescope docs/design/protocol-conventions.md, part 6).
    #
    #   socket: "@bfdd4r"          # @ is the abstract namespace, the default
    #   floor: 300000              # the least interval a client may ask for
    #   sessions:                  # with no client, for tests and labs
    #     - interface: eth1
    #       peer: 10.0.0.2
    #       local: 10.0.0.1
    #       desired_min_tx: 300000 # microseconds, as on the wire
    #       required_min_rx: 300000
    #       detect_mult: 3
    #
    # Intervals are in microseconds, the unit of RFC 5880 and of the API.
    class Config
      class Error < StandardError; end

      TOP = %w[socket floor sessions].freeze
      SESSION = %w[interface peer local desired_min_tx required_min_rx detect_mult].freeze
      DEFAULT_SOCKET = '@bfdd4r'

      attr_reader :socket, :floor, :sessions

      def self.load(path)
        new(YAML.safe_load(File.read(path), filename: path) || {})
      rescue Psych::SyntaxError, SystemCallError => e
        raise Error, e.message
      end

      def initialize(hash = {})
        raise Error, 'the file is not a YAML mapping' unless hash.is_a?(Hash)

        h = hash.transform_keys(&:to_s)
        refuse(h.keys - TOP, 'key')
        @socket = (h['socket'] || DEFAULT_SOCKET).to_s
        @floor = h.key?('floor') ? parse_floor(h['floor']) : Core::FLOOR
        @sessions = Array(h['sessions']).map { |s| session(s) }
      end

      # A session's keys, from the file or session.add: what Core#add
      # takes, without the client.
      def self.session(s)
        new('sessions' => [s]).sessions.first
      end

      # "@name" is the abstract socket "\0name"; anything else a path.
      def self.socket_path(name)
        name.start_with?('@') ? "\0#{name[1..]}" : name
      end

      private

      def session(s)
        raise Error, "a sessions entry is not a mapping: #{s.inspect}" unless s.is_a?(Hash)

        s = s.transform_keys(&:to_s)
        refuse(s.keys - SESSION, 'session key')
        out = {}
        %w[interface peer local].each do |k|
          out[k.to_sym] = s[k]&.to_s or raise Error, "a session needs #{k}"
        end
        %w[desired_min_tx required_min_rx detect_mult].each do |k|
          next unless s.key?(k)

          out[k.to_sym] = Integer(s[k])
        rescue ArgumentError, TypeError
          raise Error, "#{k} #{s[k].inspect} is not a whole number"
        end
        out
      end

      def parse_floor(value)
        n = Integer(value)
        raise ArgumentError unless n.positive?

        n
      rescue ArgumentError, TypeError
        raise Error, "floor #{value.inspect} is not a positive number of microseconds"
      end

      def refuse(keys, what)
        raise Error, "unknown #{what} #{keys.join(', ')}" unless keys.empty?
      end
    end
  end
end
