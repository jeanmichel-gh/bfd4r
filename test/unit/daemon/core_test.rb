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

# Daemon::Core against a recording transport on a manual clock: shared
# sessions, demultiplexing, counters and events. Two daemons together
# are in test/functional/daemons_test.rb.
class Core_Test < Test::Unit::TestCase
  include BFD

  # What Core sends, kept.
  class Wire
    attr_reader :sent

    def initialize
      @sent = []
    end

    def deliver(octets, interface:, peer:, local:)
      @sent << [interface, peer, local, BFD::Control.new(octets)]
    end
  end

  def setup
    @clock = Runtime::ManualClock.new
    @scheduler = Runtime::Scheduler.new(@clock)
    @wire = Wire.new
    @core = Daemon::Core.new(transport: @wire, scheduler: @scheduler, random: Random.new(1))
  end

  def add(client = 'isisd', **timers)
    @core.add(interface: 'eth1', peer: '10.0.0.2', local: '10.0.0.1', client: client, **timers)
  end

  # A packet from the peer, discriminator 9.
  def from_peer(entry, state, **fields)
    your = %i[down admin_down].include?(state) ? 0 : entry.session.local_discr
    Control.new({ state: state, my_discr: 9, your_discr: your, desired_min_tx: 300_000,
                  required_min_rx: 300_000 }.merge(fields)).encode
  end

  def receive(octets, source: '10.0.0.2', interface: 'eth1', ttl: 255)
    @core.receive(octets, interface: interface, source: source, ttl: ttl)
  end

  def test_a_session_starts_sending_at_once
    e = add
    assert_equal 1, @wire.sent.size
    interface, peer, local, packet = @wire.sent[0]
    assert_equal ['eth1', '10.0.0.2', '10.0.0.1', :down], [interface, peer, local, packet.state_name]
    assert_equal e.session.local_discr, packet.my_discr
  end

  # routescope docs/design/bfd.md: FRR's defaults, 300 ms x 3.
  def test_the_defaults_are_frrs
    s = add.session
    assert_equal [300_000, 300_000, 3], [s.desired_min_tx, s.required_min_rx_interval, s.detect_mult]
  end

  # docs/timing.md: 300 ms held for an hour with every core busy.
  def test_timers_are_checked
    assert_raise(ArgumentError) { add(hold: 3) }
    assert_raise(ArgumentError) { add(desired_min_tx: 299_999) }
    assert_raise(ArgumentError) { add(required_min_rx: 299_999) }
    assert_nothing_raised { add(desired_min_tx: 300_000, required_min_rx: 300_000) }
  end

  def test_the_floor_may_be_lowered
    core = Daemon::Core.new(transport: @wire, scheduler: @scheduler, random: Random.new(1), floor: 50_000)
    assert_equal 50_000, core.floor
    assert_raise(ArgumentError) { core.add(interface: 'eth1', peer: '10.0.0.2', local: '10.0.0.1', client: 'isisd', desired_min_tx: 49_999) }
    e = core.add(interface: 'eth1', peer: '10.0.0.2', local: '10.0.0.1', client: 'isisd', desired_min_tx: 50_000)
    assert_equal 50_000, e.session.desired_min_tx
    assert_raise(ArgumentError) { Daemon::Core.new(transport: @wire, scheduler: @scheduler, floor: 0) }
  end

  # RFC 5882 4.4: one session for every client that asks.
  def test_clients_share_a_session
    a = add('isisd')
    b = add('bgp4rd', desired_min_tx: 500_000)
    assert_same a, b
    assert_equal %w[isisd bgp4rd], a.clients
    assert_equal 300_000, a.session.desired_min_tx, 'the first to ask sets the timers'
    assert_equal 1, @core.entries.size
  end

  def test_the_session_goes_when_the_last_client_lets_go
    e = add('isisd')
    add('bgp4rd')
    @core.delete(interface: 'eth1', peer: '10.0.0.2', client: 'isisd')
    assert_equal :down, e.session.session_state
    @core.delete(interface: 'eth1', peer: '10.0.0.2', client: 'bgp4rd')
    assert_equal :admin_down, e.session.session_state
    assert_equal :admin_down, @wire.sent.last[3].state_name, 'AdminDown is sent (RFC 5880 6.8.16)'
    @scheduler.run_until(0.9)
    assert_equal 1, @core.entries.size, 'kept a Detection Time'
    @scheduler.run_until(1.1)
    assert_equal 0, @core.entries.size
    count = @wire.sent.size
    @scheduler.run_until(5.0)
    assert_equal count, @wire.sent.size, 'and silent after'
  end

  def test_asked_for_again_while_it_goes
    e = add('isisd')
    @core.delete(interface: 'eth1', peer: '10.0.0.2', client: 'isisd')
    assert_same e, add('ospfd')
    assert_equal :down, e.session.session_state
    @scheduler.run_until(5.0)
    assert_equal 1, @core.entries.size
  end

  def test_an_unknown_session_is_refused
    assert_raise(ArgumentError) { @core.delete(interface: 'eth1', peer: '10.0.0.9', client: 'x') }
    assert_raise(ArgumentError) { @core.admin(interface: 'eth1', peer: '10.0.0.9', down: true) }
  end

  def test_discriminators_are_unique
    discrs = (1..200).map { |i| @core.add(interface: 'eth1', peer: "10.0.1.#{i}", local: '10.0.0.1', client: 'x') }
                     .map { _1.session.local_discr }
    assert_equal 200, discrs.uniq.size
  end

  # RFC 5880 6.8.6: demultiplexing.

  def test_your_discriminator_zero_finds_the_session_by_source
    e = add
    assert_same e, receive(from_peer(e, :down))
    assert_equal [:init, 1], [e.session.session_state, e.counters[:packets_in]]
  end

  def test_your_discriminator_finds_the_session
    e = add
    receive(from_peer(e, :down))
    assert_same e, receive(from_peer(e, :init))
    assert_equal :up, e.session.session_state
  end

  def test_a_packet_for_no_session_is_counted
    e = add
    assert_nil receive(from_peer(e, :down), source: '10.0.0.3')
    assert_nil receive(from_peer(e, :up, your_discr: e.session.local_discr ^ 1))
    assert_nil receive(from_peer(e, :up), source: '10.0.0.3')
    assert_equal({ unknown_peer: 1, your_discr_unknown: 1, wrong_source: 1 }, @core.counters[:no_session])
  end

  def test_discards_are_counted_by_finding
    e = add
    receive(from_peer(e, :down), ttl: 254)
    receive(from_peer(e, :down, detect_mult: 0))
    receive(from_peer(e, :down).byteslice(0, 20))
    assert_equal({ ttl_not_255: 1, detect_mult_zero: 1, truncated: 1 }, e.counters[:discards])
    assert_equal :down, e.session.session_state
  end

  def test_admin_and_set
    e = add
    receive(from_peer(e, :down))
    receive(from_peer(e, :up))
    @core.set(interface: 'eth1', peer: '10.0.0.2', desired_min_tx: 1_000_000)
    assert e.session.polling?
    assert_raise(ArgumentError) { @core.set(interface: 'eth1', peer: '10.0.0.2', desired_min_tx: 10) }
    @core.admin(interface: 'eth1', peer: '10.0.0.2', down: true)
    assert_equal :admin_down, e.session.session_state
    @core.admin(interface: 'eth1', peer: '10.0.0.2', down: false)
    assert_equal :down, e.session.session_state
  end

  def test_flaps_and_time_in_state
    e = add
    receive(from_peer(e, :down))
    receive(from_peer(e, :up))
    @scheduler.run_until(2.0)
    assert_equal [:down, 1], [e.session.session_state, e.counters[:flaps]]
    row = @core.show.first
    assert_in_delta 2.0 - 0.9, row[:in_state], 1e-9
  end

  def test_show_has_every_variable_and_count
    e = add
    receive(from_peer(e, :down))
    row = @core.show.first
    assert_equal %i[interface peer local clients state variables tx_interval detection_time polling since in_state
                    packets_in packets_out flaps discards], row.keys
    assert_equal Session::VARIABLES.keys, row[:variables].keys
    assert_equal [:init, 1, 2], row.values_at(:state, :packets_in, :packets_out)
  end

  def test_events_say_what_happened
    e = add
    receive(from_peer(e, :down))
    kinds = @core.events.since(0).map { [_1.kind, _1.session, _1.level] }
    assert_equal [[:config, 'eth1 10.0.0.2', :info], [:session, 'eth1 10.0.0.2', :info]], kinds
    assert_equal({ from: :down, to: :init, diag: :none, interface: 'eth1', peer: '10.0.0.2' },
                 @core.events.since(1).first.data)
    @scheduler.run_until(5.0)
    assert_equal :warn, @core.events.since(0).last.level, 'going Down is a warning'
  end
end
