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

# Two daemon cores on one manual clock, joined by Daemon::Loopback, as
# two bfdd4r on either side of a link. The programs and their sockets
# join this tier in steps 4b and 4c.
class Daemons_Test < Test::Unit::TestCase
  include BFD

  A = '10.0.0.1'
  B = '10.0.0.2'

  def setup
    @clock = Runtime::ManualClock.new
    @scheduler = Runtime::Scheduler.new(@clock)
    @net = Daemon::Loopback.new(@scheduler)
    @a = Daemon::Core.new(transport: @net.port(A), scheduler: @scheduler, random: Random.new(1))
    @b = Daemon::Core.new(transport: @net.port(B), scheduler: @scheduler, random: Random.new(2))
    @net.attach(A, @a, interface: 'eth1')
    @net.attach(B, @b, interface: 'eth2')
  end

  def both(client = 'isisd', **timers)
    @a.add(interface: 'eth1', peer: B, local: A, client: client, **timers)
    @b.add(interface: 'eth2', peer: A, local: B, client: client, **timers)
  end

  def a_session = @a.entry(interface: 'eth1', peer: B)
  def b_session = @b.entry(interface: 'eth2', peer: A)

  def states
    [a_session&.session&.session_state, b_session&.session&.session_state]
  end

  def session_events(core)
    core.events.since(0).select { _1.kind == :session }.map { [_1.data[:to], _1.data[:diag]] }
  end

  def test_two_daemons_come_up
    both
    @scheduler.run_until(0.01)
    assert_equal %i[up up], states
    @scheduler.run_until(10.0)
    assert_equal %i[up up], states
    row = @a.show.first
    assert_equal [300_000, 900_000, 0], row.values_at(:tx_interval, :detection_time, :flaps)
    assert_operator row[:packets_in], :>, 25
    assert_equal({}, row[:discards])
  end

  def test_a_lost_direction
    both
    @scheduler.run_until(2.0)
    @net.cut(B)
    @scheduler.run_until(4.0)
    assert_include session_events(@a), %i[down control_detection_time_expired]
    assert_include session_events(@b), %i[down neighbor_signaled_session_down]
    assert_equal 1, a_session.counters[:flaps]
    @net.cut(B, false)
    @scheduler.run_until(8.0)
    assert_equal %i[up up], states
  end

  # RFC 5881 5: without authentication, a TTL other than 255 is
  # discarded, so the session fails.
  def test_a_ttl_of_254_takes_the_session_down
    both
    @scheduler.run_until(2.0)
    @net.ttl(A, 254)
    @scheduler.run_until(4.0)
    assert_equal :down, b_session.session.session_state
    assert_operator b_session.counters[:discards][:ttl_not_255], :>, 3
  end

  # RFC 5882 4.4: a session shared by two clients on each side stays
  # while either holds it.
  def test_a_shared_session_outlives_one_client
    both('isisd')
    both('bgp4rd')
    @scheduler.run_until(1.0)
    @a.delete(interface: 'eth1', peer: B, client: 'isisd')
    @scheduler.run_until(3.0)
    assert_equal %i[up up], states
    assert_equal ['bgp4rd'], a_session.clients
  end

  # The last client gone: AdminDown is sent, the far side goes Down with
  # diagnostic 3, which RFC 5882 4.2 says is not a failure, and stays
  # Down; the near side forgets the session.
  def test_the_last_client_gone
    both
    @scheduler.run_until(1.0)
    @a.delete(interface: 'eth1', peer: B, client: 'isisd')
    @scheduler.run_until(5.0)
    assert_nil a_session
    assert_equal :down, b_session.session.session_state
    assert_equal %i[down neighbor_signaled_session_down], session_events(@b).find { _1[0] == :down }
    assert_equal 1, b_session.counters[:flaps], 'one flap, from Up'
  end

  def test_a_timer_change_runs_a_poll_sequence
    both
    @scheduler.run_until(1.0)
    @a.set(interface: 'eth1', peer: B, required_min_rx: 1_000_000)
    @scheduler.run_until(1.5)
    refute a_session.session.polling?, 'the Final came back'
    assert_equal 1_000_000, b_session.session.tx_interval
    assert_equal 3_000_000, a_session.session.detection_time
    @scheduler.run_until(10.0)
    assert_equal %i[up up], states
  end

  def test_admin_down_and_back
    both
    @scheduler.run_until(1.0)
    @a.admin(interface: 'eth1', peer: B, down: true)
    @scheduler.run_until(3.0)
    assert_equal %i[admin_down down], states
    @a.admin(interface: 'eth1', peer: B, down: false)
    @scheduler.run_until(6.0)
    assert_equal %i[up up], states
  end
end
