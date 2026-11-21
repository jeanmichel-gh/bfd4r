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
require 'bfd4r'

# The injector's actions, refusals and reads, on a manual clock, with a
# transport that records what it is asked to send.
class Injector_Test < Test::Unit::TestCase
  include BFD

  class Wire
    attr_reader :sent, :listening

    def initialize(busy: false)
      @sent = []
      @busy = busy
    end

    def deliver(octets, **k)
      @sent << [octets, k]
    end

    def listen(local)
      raise Errno::EADDRINUSE, local if @busy

      @listening = local
    end
  end

  def setup
    @clock = Runtime::ManualClock.new
    @scheduler = Runtime::Scheduler.new(@clock)
    @wire = Wire.new
    @sim = sim(@wire)
  end

  def sim(wire)
    Sim::Injector.new(transport: wire, scheduler: @scheduler, local: '10.0.0.2', interface: 'eth1',
                      random: Random.new(1))
  end

  def last
    octets, k = @wire.sent.last
    [Control.new(octets), k]
  end

  def test_send_any_field_ttl_and_port
    a = @sim.act('send', 'to' => '10.0.0.1', 'state' => 'init', 'my_discr' => 5, 'your_discr' => 6,
                         'detect_mult' => 7, 'poll' => true, 'ttl' => 1, 'source_port' => 50_000)
    assert_equal [1, '10.0.0.1', 24, 1], [a[:sent], a[:to], a[:octets], a[:ttl]]
    p, k = last
    assert_equal [:init, 5, 6, 7, true], [p.state_name, p.my_discr, p.your_discr, p.detect_mult, p.poll?]
    assert_equal({ interface: 'eth1', peer: '10.0.0.1', local: '10.0.0.2', ttl: 1, source_port: 50_000 }, k)
    assert_equal 1, @sim.sent[:send]
    assert_nil @wire.listening, 'a send binds no port 3784'
  end

  def test_send_octets
    @sim.act('send', 'to' => 'fd00::1', 'octets' => '20c0')
    assert_equal ["\x20\xc0".b, 255], [@wire.sent.last[0], @wire.sent.last[1][:ttl]]
  end

  def test_a_send_to_the_peer_takes_its_discriminators
    @sim.act('peer', 'to' => '10.0.0.1')
    @sim.act('send', 'to' => '10.0.0.1', 'state' => 'up')
    p, = last
    assert_equal [@sim.status[:peer][:local_discr], 0], [p.my_discr, p.your_discr]
  end

  def test_refusals
    {
      ['send', { 'to' => '10.0.0.1', 'hold' => 1 }] => /send takes .* not hold/,
      ['send', {}] => /to: the peer/,
      ['send', { 'to' => 'nowhere' }] => /not an address/,
      ['send', { 'to' => '10.0.0.1', 'ttl' => 256 }] => /ttl/,
      ['send', { 'to' => '10.0.0.1', 'source_port' => 0 }] => /source_port/,
      ['send', { 'to' => '10.0.0.1', 'octets' => 'abc' }] => /octets/,
      ['send', { 'to' => '10.0.0.1', 'detect_mult' => 256 }] => /detect_mult/,
      ['fault', { 'case' => 'nope', 'to' => '10.0.0.1' }] => /case "nope": one of truncated/,
      ['fault', { 'case' => 'multipoint', 'to' => '10.0.0.1' }] => /my_discr: give it/,
      ['fault', { 'case' => 'multipoint' }] => /needs to, or a peer session/,
      ['behave', { 'name' => 'silent' }] => /no peer session/,
      ['peer', { 'to' => '10.0.0.1', 'behaviour' => 'sulk' }] => /behaviour "sulk": one of silent/,
      ['peer', { 'to' => '10.0.0.1', 'after' => -1 }] => /after/,
      ['peer', { 'to' => '10.0.0.1', 'detect_mult' => 0 }] => /detect_mult/,
      ['jump', {}] => /unknown action jump/
    }.each do |(action, body), message|
      e = assert_raise(Sim::Refused, action) { @sim.act(action, body) }
      assert_match(message, e.message)
    end
    assert_equal [], @wire.sent
  end

  def test_one_peer_session_at_a_time
    @sim.act('peer', 'to' => '10.0.0.1')
    assert_equal '10.0.0.2', @wire.listening
    assert_raise(Sim::Busy) { @sim.act('peer', 'to' => '10.0.0.3') }
    @sim.act('behave', 'name' => 'flap')
    e = assert_raise(Sim::Busy) { @sim.act('behave', 'name' => 'silent') }
    assert_match(/flap is running/, e.message)
  end

  def test_a_bfdd4r_holding_the_port_is_busy
    e = assert_raise(Sim::Busy) { sim(Wire.new(busy: true)).act('peer', 'to' => '10.0.0.1') }
    assert_match(/port 3784.*bfdd4r/, e.message)
  end

  def test_a_fault_with_given_discriminators
    a = @sim.act('fault', 'case' => 'ttl_254', 'to' => '10.0.0.1', 'my_discr' => 3, 'your_discr' => 4)
    assert_equal [:ttl_not_255, :discard, 'RFC 5881 5', 254], a.values_at(:finding, :expect, :rfc, :ttl)
    p, k = last
    assert_equal [3, 4, 254], [p.my_discr, p.your_discr, k[:ttl]]
    assert_equal({ ttl_254: 1 }, @sim.sent[:fault])
  end

  def test_a_fault_to_the_peer_uses_the_session
    @sim.act('peer', 'to' => '10.0.0.1')
    reply = Control.new(state: :down, my_discr: 77, your_discr: 0, desired_min_tx: 1_000_000,
                        required_min_rx: 1_000_000)
    @sim.receive(reply.encode, interface: 'eth1', source: '10.0.0.1', ttl: 255)
    @sim.act('fault', 'case' => 'multipoint')
    p, = last
    assert_equal [@sim.status[:peer][:local_discr], 77, true], [p.my_discr, p.your_discr, p.multipoint?]
  end

  def test_received
    @sim.act('peer', 'to' => '10.0.0.1')
    @sim.receive('short'.b, source: '10.0.0.9', ttl: 64)
    @sim.receive(Control.new(state: :up, my_discr: 0).encode, source: '10.0.0.1', ttl: 255)
    r = @sim.received
    assert_equal [2, 1, { my_discr_zero: 1, your_discr_zero_up: 1 }], r.values_at(:packets, :from_peer, :discards)
    assert_equal({ from: '10.0.0.9', ttl: 64, octets: 5, undecoded: true }, r[:last][0])
    assert_equal ['10.0.0.1', :up, 0], r[:last][1].values_at(:from, :state, :my_discr)
  end

  def test_events
    @sim.act('peer', 'to' => '10.0.0.1')
    @sim.act('fault', 'case' => 'multipoint', 'your_discr' => 1)
    e = @sim.events_since('since' => '0')
    assert_equal %w[peer fault], e[:events].map { _1[:kind] }
    assert_equal 1, @sim.events_since('since' => '1')[:events].size
    assert_raise(Sim::Refused) { @sim.events_since('since' => 'x') }
  end

  def test_catalog
    c = @sim.catalog
    assert_equal Fault.names, c[:faults].map { _1[:name] }
    assert_equal Behaviour::SCRIPTS.keys, c[:behaviours].map { _1[:name] }
    assert(c[:faults].none? { _1.key?(:build) })
  end

  def test_stop_with_nothing_running
    assert_equal({ stopped: nil }, @sim.act('stop', {}))
  end
end
