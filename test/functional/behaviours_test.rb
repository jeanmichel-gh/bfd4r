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
require_relative '../support/pair'

# Our session against each Behaviour, joined on a manual clock, and what
# RFC 5880 expects of our session in each case (BFD::Behaviour::SCRIPTS).
# Later, bfdd4r and bfd4r-sim run the same scripts over sockets.
class Behaviours_Test < Test::Unit::TestCase
  include BFD

  # Ours is a, the misbehaving peer b. Both come Up at once unless the
  # script stops it.
  def run_script(name, seconds: 6.0)
    r = Random.new(5)
    pr = Pair.new(a: Session.new(local_discr: 1, random: r), b: Behaviour.new(name, local_discr: 2, random: r))
    pr.start.run_until(seconds)
  end

  def ours(pr)
    pr.changes(pr.a).map { [_1.action.to, _1.action.diag] }
  end

  def test_every_script_is_run_here
    tested = Behaviours_Test.instance_methods.grep(/\Atest_/).map(&:to_s)
    Behaviour::SCRIPTS.each_key { |name| assert(tested.any? { _1.end_with?(name.to_s) }, name.to_s) }
  end

  # RFC 5880 6.8.4: Down with diagnostic 1 within the Detection Time of
  # the peer's last packet.
  def test_silent
    pr = run_script(:silent)
    last = pr.sent(pr.b).last.time
    down = pr.changes(pr.a).find { _1.action.to == :down }
    assert_equal [:down, :control_detection_time_expired], [down.action.to, down.action.diag]
    assert_operator down.time - last, :<=, 0.9 + 0.001
    assert_operator down.time - last, :>, 0.85
  end

  # RFC 5880 6.8.3: a slower interval waits for the Final, which never
  # comes; the Poll Sequence keeps going.
  def test_no_final
    pr = run_script(:no_final, seconds: 1.0)
    pr.call(pr.a) { |s, now| s.set(now, desired_min_tx: 1_000_000) }
    pr.run_for(5.0)
    assert pr.a.polling?
    assert_equal 300_000, pr.a.tx_interval
    assert_equal :up, pr.a.session_state
    polls = pr.sent(pr.a).select { _1.time > 1.0 && _1.action.packet.poll? }
    assert_operator polls.size, :>=, 15, 'the Poll goes on every periodic packet'
  end

  # RFC 5880 6.2 and 6.8.3: a peer that says Down holds us in Init, and
  # its pace does not make ours faster than one a second.
  def test_fast_while_down
    pr = run_script(:fast_while_down)
    assert_equal :init, pr.a.session_state
    assert_operator pr.sent(pr.b).size, :>, 50
    periodic = pr.sent(pr.a).map(&:time).select { _1 > 0.01 }
    gaps = periodic.each_cons(2).map { _2 - _1 }
    assert(gaps.all? { _1.between?(0.75, 1.0) }, gaps.inspect)
    assert(pr.sent(pr.a).all? { _1.action.packet.desired_min_tx == 1_000_000 })
  end

  # RFC 5880 6.8.6: AdminDown received takes us Down with diagnostic 3.
  # RFC 5882 4.2: that is not a failure for the clients.
  def test_admin_down
    pr = run_script(:admin_down)
    assert_equal [[:init, :none], [:up, :none], [:down, :neighbor_signaled_session_down]], ours(pr)
    assert_equal :admin_down, pr.b.session_state
  end

  def test_flap
    pr = run_script(:flap, seconds: 8.0)
    downs = pr.changes(pr.a).select { _1.action.to == :down }
    ups = pr.changes(pr.a).select { _1.action.to == :up }
    assert_equal 4, downs.size
    assert_equal 4, ups.size
    assert(downs.all? { _1.action.diag == :neighbor_signaled_session_down })
  end

  # RFC 5880 6.3: our session is found by our discriminator, so the peer
  # changing its own does not matter: we stay Up and learn the new one.
  def test_discr_change
    pr = run_script(:discr_change)
    assert_equal [[:init, :none], [:up, :none]], ours(pr)
    assert_equal 2 ^ 0x0101_0101, pr.a.remote_discr
  end

  # RFC 5880 6.8.6: Down receiving Up stays Down.
  def test_skip_init
    pr = run_script(:skip_init)
    assert_equal [], ours(pr)
    assert_equal :down, pr.a.session_state
    assert(pr.sent(pr.b).all? { _1.action.packet.state_name == :up })
  end

  # RFC 5880 6.8.7: the transmit interval is the greater of ours and the
  # peer's Required Min RX, from the packet that carries it.
  def test_slow_rx
    pr = run_script(:slow_rx, seconds: 6.0)
    assert_equal 1_000_000, pr.a.tx_interval
    raised = pr.sent(pr.b).find { _1.action.packet.required_min_rx == 1_000_000 }.time
    after = pr.sent(pr.a).map(&:time).select { _1 > raised + 0.5 }
    gaps = after.each_cons(2).map { _2 - _1 }
    assert(gaps.all? { _1.between?(0.75, 1.0) }, gaps.inspect)
  end
end
