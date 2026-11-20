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

require 'test/unit'
require 'socket'
require 'bfd/daemon/udp'

# Daemon::Udp on 127.0.0.1, on a port of its own so it meets no bfdd4r:
# what RFC 5881 asks of the sender, and what it reads back.
class Udp_Test < Test::Unit::TestCase
  include BFD::Daemon

  def setup
    probe = Socket.new(:INET, :DGRAM)
    probe.bind(Addrinfo.udp('127.0.0.1', 0))
    @port = probe.local_address.ip_port
    probe.close
    @got = Thread::Queue.new
    @udp = Udp.new(port: @port, random: Random.new(1))
    @udp.on_packet = ->(octets, **k) { @got.push([octets, k]) }
  end

  def teardown
    @udp.close
  end

  # RFC 5881 4: a source port in 49152 to 65535, the same for the life
  # of the session.
  def test_source_ports
    ports = (2..41).map do |i|
      @udp.deliver('x', interface: nil, peer: "127.0.0.#{i}", local: '127.0.0.1')
      @udp.source_port(interface: nil, peer: "127.0.0.#{i}")
    end
    assert(ports.all? { (49_152..65_535).cover?(_1) }, ports.minmax.inspect)
    @udp.deliver('y', interface: nil, peer: '127.0.0.2', local: '127.0.0.1')
    assert_equal ports[0], @udp.source_port(interface: nil, peer: '127.0.0.2')
  end

  def test_the_range_is_rfc_5881s
    assert_equal 49_152..65_535, Udp::SOURCE_PORTS
    assert_equal 3784, Udp::PORT
  end

  # A packet to itself: TTL 255 sent (section 5), and read back with the
  # interface and source.
  def test_ttl_255_is_sent_and_read_back
    @udp.deliver("\x20\x40".b, interface: 'lo', peer: '127.0.0.1', local: '127.0.0.1')
    octets, k = @got.pop(timeout: 5)
    assert_equal "\x20\x40".b, octets
    assert_equal({ interface: 'lo', source: '127.0.0.1', ttl: 255 }, k)
  end

  def test_released_sessions_get_a_new_socket
    @udp.deliver('x', interface: nil, peer: '127.0.0.2', local: '127.0.0.1')
    assert_not_nil @udp.source_port(interface: nil, peer: '127.0.0.2')
    @udp.release(interface: nil, peer: '127.0.0.2')
    assert_nil @udp.source_port(interface: nil, peer: '127.0.0.2')
  end
end
