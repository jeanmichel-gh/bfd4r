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

  # bfd4r-sim's sends: a TTL for one packet, then 255 again; a source
  # port of its choosing.
  def test_a_ttl_and_a_source_port_for_one_packet
    @udp.deliver('a', interface: 'lo', peer: '127.0.0.1', local: '127.0.0.1', ttl: 254)
    assert_equal ['a', 254], @got.pop(timeout: 5).then { [_1[0], _1[1][:ttl]] }
    @udp.deliver('b', interface: 'lo', peer: '127.0.0.1', local: '127.0.0.1')
    assert_equal ['b', 255], @got.pop(timeout: 5).then { [_1[0], _1[1][:ttl]] }
    listener = Socket.new(:INET, :DGRAM)
    listener.bind(Addrinfo.udp('127.0.0.3', @port))
    @udp.deliver('c', interface: nil, peer: '127.0.0.3', local: '127.0.0.1', source_port: 40_000)
    _, from = listener.recvfrom(10)
    assert_equal 40_000, from.ip_port
    @udp.deliver('d', interface: nil, peer: '127.0.0.3', local: '127.0.0.1')
    _, from = listener.recvfrom(10)
    assert_equal @udp.source_port(interface: nil, peer: '127.0.0.3'), from.ip_port, 'the kept socket again'
  ensure
    listener&.close
  end

  # With listen: false, nothing binds the receive port until listen.
  def test_listen_false_binds_only_when_told
    quiet = Udp.new(port: @port, listen: false)
    quiet.deliver('x', interface: nil, peer: '127.0.0.2', local: '127.0.0.4')
    probe = Socket.new(:INET, :DGRAM)
    assert_nothing_raised { probe.bind(Addrinfo.udp('127.0.0.4', @port)) }
    assert_raise(Errno::EADDRINUSE) { quiet.listen('127.0.0.4') }
    probe.close
    quiet.listen('127.0.0.4')
    assert_raise(Errno::EADDRINUSE) { Socket.new(:INET, :DGRAM).bind(Addrinfo.udp('127.0.0.4', @port)) }
  ensure
    quiet&.close
  end

  def test_released_sessions_get_a_new_socket
    @udp.deliver('x', interface: nil, peer: '127.0.0.2', local: '127.0.0.1')
    assert_not_nil @udp.source_port(interface: nil, peer: '127.0.0.2')
    @udp.release(interface: nil, peer: '127.0.0.2')
    assert_nil @udp.source_port(interface: nil, peer: '127.0.0.2')
  end

  # An interface's VRF, read once and kept until a session on it is
  # released (routescope docs/design/bfd-vrf.md). 'default' outside one,
  # as FRR names it.
  def test_the_vrf_of_an_interface
    asked = []
    udp = Udp.new(port: @port, vrf_of: ->(i) { asked << i; { 'eth3' => 'A' }[i] })
    assert_equal %w[A A default], [udp.vrf_name('eth3'), udp.vrf_name('eth3'), udp.vrf_name('eth1')]
    assert_equal %w[eth3 eth1], asked
    udp.release(interface: 'eth3', peer: '192.168.1.2')
    udp.vrf_name('eth3')
    assert_equal %w[eth3 eth1 eth3], asked, 'read again after a release'
    assert_equal 'default', udp.vrf_name(nil)
  ensure
    udp&.close
  end

  # A receiver in a VRF is bound to the VRF's device. One that cannot
  # be, here a device that is not there, is not kept, and the send says
  # why. test/interop/vrf_test.rb runs it in two real VRFs.
  def test_a_receiver_in_a_vrf_binds_its_device
    logged = []
    udp = Udp.new(port: @port, vrf_of: ->(_) { 'no-such-vrf' }, logger: ->(l, m) { logged << [l, m] })
    udp.deliver('x', interface: 'lo', peer: '127.0.0.1', local: '127.0.0.1')
    assert_equal [:warn], logged.map(&:first), logged.inspect
    assert_match(/send to 127.0.0.1 on lo: /, logged.first[1])
    assert_equal({}, udp.instance_variable_get(:@receivers))
  ensure
    udp&.close
  end

  # What iproute2 says of an interface in no VRF.
  def test_lo_is_in_no_vrf
    omit('no ip command') unless system('ip -V', out: File::NULL, err: File::NULL)
    udp = Udp.new(port: @port)
    assert_equal 'default', udp.vrf_name('lo')
  ensure
    udp&.close
  end
end
