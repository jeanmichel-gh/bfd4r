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
require 'ipaddr'

module BFD
  module Sim
    # bfd4r-sim's file:
    #
    #   local: 10.0.12.1        the address it sends from
    #   interface: eth1         the interface it sends on (optional)
    #   api: 127.0.0.1:8080     its HTTP API (the loopback by default)
    #
    # An injector keeps no sessions from a file, so bfdd4r's keys are
    # refused by name, as vtep4r-sim refuses vtep4rd's: its sessions come
    # from POST /api/peer, one at a time.
    class Config
      class Error < StandardError; end

      KEYS = %w[local interface api].freeze
      DAEMON_KEYS = %w[sessions socket floor].freeze

      attr_reader :local, :interface, :api

      def self.load(path)
        new(YAML.safe_load(File.read(path), filename: path) || {})
      rescue Psych::SyntaxError, SystemCallError => e
        raise Error, e.message
      end

      def initialize(hash)
        raise Error, 'the file is not a YAML mapping' unless hash.is_a?(Hash)

        h = hash.transform_keys(&:to_s)
        daemon = h.keys & DAEMON_KEYS
        raise Error, "#{daemon.join(', ')}: that is bfdd4r's file; bfd4r-sim's peer comes from POST /api/peer" unless daemon.empty?

        unknown = h.keys - KEYS
        raise Error, "unknown key #{unknown.join(', ')}; bfd4r-sim's file takes #{KEYS.join(', ')}" unless unknown.empty?

        @local = h['local'] or raise Error, 'local: the address to send from is required'
        @local = @local.to_s
        IPAddr.new(@local)
        @interface = h['interface']&.to_s
        @api = (h['api'] || '127.0.0.1:8080').to_s
      rescue IPAddr::Error
        raise Error, "local: #{h['local'].inspect} is not an address"
      end
    end
  end
end
