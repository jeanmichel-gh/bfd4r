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
require 'bfd/daemon/events'

class Events_Test < Test::Unit::TestCase
  Events = BFD::Daemon::Events

  T = Time.utc(2026, 11, 20, 21, 20, 0.123r)

  def ev(backlog: 2000, max_queue: 10_000)
    Events.new(backlog: backlog, max_queue: max_queue, clock: -> { T })
  end

  # bgp4r's shape, so routescope reads it as it reads bgp4rd's.
  def test_an_event_in_bgp4rs_shape
    e = ev.publish(:session, 'eth1 10.0.0.2 init -> up (none)', session: 'eth1 10.0.0.2', data: { to: 'up' })
    assert_equal({ seq: 1, time: '2026-11-20T21:20:00.123Z', level: 'info', kind: 'session', session: 'eth1 10.0.0.2',
                   message: 'eth1 10.0.0.2 init -> up (none)', data: { to: 'up' } }, e.to_h)
  end

  def test_an_unknown_kind_is_refused
    assert_raise(ArgumentError) { ev.publish(:mac, 'x') }
    assert_raise(ArgumentError) { ev.subscribe(kinds: %w[mac]) }
  end

  def test_since
    e = ev
    3.times { |i| e.publish(:session, "m#{i}") }
    assert_equal [2, 3], e.since(1).map(&:seq)
    assert_equal [], e.since(3)
  end

  def test_since_a_sequence_no_longer_kept_says_so
    e = ev(backlog: 2)
    5.times { |i| e.publish(:session, "m#{i}") }
    out = e.since(0)
    assert_equal [:overflow, :session, :session], out.map(&:kind)
    assert_equal({ reason: 'backlog', lost: 3 }, out[0].data)
    assert_equal [4, 5], out.drop(1).map(&:seq)
  end

  def test_a_subscription_gets_what_comes_after_and_its_kinds_only
    e = ev
    e.publish(:session, 'before')
    sub = e.subscribe(kinds: %w[session])
    e.publish(:config, 'd')
    e.publish(:session, 'after')
    assert_equal ['after'], sub.take(0).map(&:message)
    assert_equal [], sub.take(0.01)
  end

  def test_a_subscription_with_since_replays
    e = ev
    e.publish(:session, 'a')
    e.publish(:session, 'b')
    sub = e.subscribe(since: 1)
    assert_equal 1, sub.replayed
    assert_equal ['b'], sub.take(0).map(&:message)
  end

  def test_a_slow_reader_is_told_what_it_lost
    e = ev(max_queue: 2)
    sub = e.subscribe
    5.times { |i| e.publish(:session, "m#{i}") }
    out = sub.take(0)
    assert_equal [:overflow, :session, :session], out.map(&:kind)
    assert_equal({ reason: 'slow_reader', lost: 3 }, out[0].data)
  end

  def test_take_waits_for_the_first
    e = ev
    sub = e.subscribe
    Thread.new { sleep 0.05; e.publish(:config, 'late') }
    assert_equal ['late'], sub.take(2).map(&:message)
  end

  def test_unsubscribe
    e = ev
    sub = e.subscribe
    assert_equal 1, e.subscribers
    e.unsubscribe(sub)
    assert_equal 0, e.subscribers
  end
end
