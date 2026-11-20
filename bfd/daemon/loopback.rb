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

module BFD
  module Daemon
    # An in-memory network for daemons on one scheduler, for tests and
    # the functional tier: each daemon is attached by its addresses, and
    # a packet is delivered to the daemon that owns the peer address,
    # after a delay, as if it came in on the interface it was attached
    # with. TTL is 255 unless a test sets it. A direction can be cut.
    #
    #   net = Loopback.new(scheduler)
    #   a = Core.new(transport: net.port('10.0.0.1'), scheduler: scheduler)
    #   net.attach('10.0.0.1', a, interface: 'eth1')
    class Loopback
      # One daemon's side: what Core calls deliver on.
      class Port
        def initialize(net, address)
          @net = net
          @address = address
        end

        # ttl: this packet's, as bfd4r-sim sends; source_port is not
        # carried.
        def deliver(octets, interface:, peer:, local:, ttl: nil, source_port: nil)
          _ = source_port
          @net.carry(octets, from: local || @address, to: peer, interface: interface, ttl: ttl)
        end
      end

      attr_reader :sent

      def initialize(scheduler, delay: 0.001)
        @scheduler = scheduler
        @delay = delay
        @at = {}
        @cut = {}
        @ttl = Hash.new(255)
        # Every packet carried: [time, from, to, octets].
        @sent = []
      end

      def port(address)
        Port.new(self, address)
      end

      # core receives what is sent to address, on interface.
      def attach(address, core, interface:)
        @at[address] = [core, interface]
      end

      # Packets from address are lost while cut.
      def cut(address, on = true)
        @cut[address] = on
      end

      # Packets from address arrive with this TTL.
      def ttl(address, value)
        @ttl[address] = value
      end

      # Octets from one address to another, delivered after the delay.
      def carry(octets, from:, to:, interface: nil, ttl: nil)
        @sent << [@scheduler.now, from, to, octets]
        return if @cut[from]

        core, in_interface = @at[to]
        return unless core

        ttl ||= @ttl[from]
        @scheduler.after(@delay) { core.receive(octets, interface: in_interface, source: from, ttl: ttl) }
      end
    end
  end
end
