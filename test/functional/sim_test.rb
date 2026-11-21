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

# bfd4r-sim's injector and two bfdd4r cores on one manual clock, joined
# by Daemon::Loopback: routescope docs/design/bfd.md, "Tests",
# functional. The sim (B) runs a session to bfdd4r A, which also has a
# session to bfdd4r C. Every behaviour script runs against A, every
# fault is counted by A, and A's session to C is not disturbed.
class Sim_Test < Test::Unit::TestCase
  include BFD

  A = '10.0.0.1'
  B = '10.0.0.2'
  C = '10.0.0.3'

  def setup
    @clock = Runtime::ManualClock.new
    @scheduler = Runtime::Scheduler.new(@clock)
    @net = Daemon::Loopback.new(@scheduler)
    @a = Daemon::Core.new(transport: @net.port(A), scheduler: @scheduler, random: Random.new(1))
    @c = Daemon::Core.new(transport: @net.port(C), scheduler: @scheduler, random: Random.new(3))
    @sim = Sim::Injector.new(transport: @net.port(B), scheduler: @scheduler, local: B, interface: 'eth1',
                             random: Random.new(2))
    @net.attach(A, @a, interface: 'eth1')
    @net.attach(B, @sim, interface: 'eth1')
    @net.attach(C, @c, interface: 'eth1')
    @a.add(interface: 'eth1', peer: B, local: A, client: 'isisd')
    @a.add(interface: 'eth1', peer: C, local: A, client: 'isisd')
    @c.add(interface: 'eth1', peer: A, local: C, client: 'isisd')
  end

  def to_sim = @a.entry(interface: 'eth1', peer: B)
  def to_c = @a.entry(interface: 'eth1', peer: C)

  def changes
    @a.events.since(0).select { _1.kind == :session && _1.data[:peer] == B }.map { [_1.data[:to], _1.data[:diag]] }
  end

  def peer
    @sim.act('peer', 'to' => A)
  end

  def run_to(time)
    @scheduler.run_until(time)
  end

  # The session to C is never touched by what the sim does.
  def teardown
    return unless @clock.now >= 1.0

    assert_equal [:up, 0, {}], [to_c.session.session_state, to_c.counters[:flaps], to_c.counters[:discards]]
  end

  def test_a_peer_session_comes_up
    peer
    run_to(10.0)
    assert_equal %i[up up], [to_sim.session.session_state, @sim.status[:peer][:state]]
    assert_equal [300_000, 900_000], @sim.status[:peer].values_at(:tx_interval, :detection_time)
    assert_operator @sim.sent[:session], :>, 25
    assert_equal({}, to_sim.counters[:discards])
  end

  def test_every_behaviour_is_run_here
    tested = Sim_Test.instance_methods.grep(/\Atest_behave_/).map { _1.to_s.delete_prefix('test_behave_').to_sym }
    assert_equal Behaviour::SCRIPTS.keys.sort, tested.sort
  end

  # Each script runs from the session's first packet, as a Behaviour
  # does; its timing counts from Up.
  def behave(name)
    @sim.act('peer', 'to' => A, 'behaviour' => name.to_s)
  end

  def test_behave_silent
    behave(:silent)
    run_to(5.0)
    assert_include changes, %i[down control_detection_time_expired]
  end

  def test_behave_no_final
    behave(:no_final)
    run_to(1.0)
    @a.set(interface: 'eth1', peer: B, desired_min_tx: 1_000_000)
    run_to(6.0)
    assert to_sim.session.polling?
    assert_equal [:up, 300_000], [to_sim.session.session_state, to_sim.session.tx_interval]
  end

  def test_behave_fast_while_down
    behave(:fast_while_down)
    run_to(5.0)
    assert_equal :init, to_sim.session.session_state
    assert_operator @sim.sent[:session], :>, 40
  end

  def test_behave_admin_down
    behave(:admin_down)
    run_to(5.0)
    assert_equal [%i[init none], %i[up none], %i[down neighbor_signaled_session_down]], changes
  end

  def test_behave_flap
    behave(:flap)
    run_to(8.5)
    downs = changes.select { _1[0] == :down }
    assert_operator downs.size, :>=, 3
    assert(downs.all? { _1[1] == :neighbor_signaled_session_down })
  end

  def test_behave_discr_change
    behave(:discr_change)
    run_to(5.0)
    assert_equal [%i[init none], %i[up none]], changes
    assert_equal @sim.status[:peer][:local_discr] ^ 0x0101_0101, to_sim.session.remote_discr
  end

  def test_behave_skip_init
    behave(:skip_init)
    run_to(5.0)
    assert_equal [], changes
    assert_equal :down, to_sim.session.session_state
  end

  def test_behave_slow_rx
    behave(:slow_rx)
    run_to(5.0)
    assert_equal 1_000_000, to_sim.session.tx_interval
  end

  # A script switched on while Up counts from the switch.
  def test_a_script_on_an_up_session
    peer
    run_to(3.0)
    @sim.act('behave', 'name' => 'silent', 'after' => 2.0)
    run_to(4.5)
    assert_equal :up, to_sim.session.session_state
    run_to(7.0)
    assert_include changes, %i[down control_detection_time_expired]
  end

  # fast_while_down switched on while Up: the peer says Down at once and
  # every 100 ms, which takes bfdd4r Down and holds it in Init.
  def test_fast_while_down_on_an_up_session
    peer
    run_to(2.0)
    sent = @sim.sent[:session]
    @sim.act('behave', 'name' => 'fast_while_down')
    run_to(4.0)
    assert_equal :init, to_sim.session.session_state
    assert_operator @sim.sent[:session] - sent, :>=, 19
  end

  def test_stop_ends_the_script_then_the_session
    behave(:silent)
    run_to(0.5)
    assert_equal({ stopped: 'script', behaviour: :silent }, @sim.act('stop', 'script' => true))
    run_to(5.0)
    assert_equal :up, to_sim.session.session_state, 'well behaved again'
    assert_equal 'session', @sim.act('stop', {})[:stopped]
    run_to(5.1)
    assert_equal %i[down neighbor_signaled_session_down], changes.last
    assert_nil @sim.status[:peer]
  end

  # Every fault for a receiver without authentication is counted by
  # bfdd4r under its finding, or for :record, accepted. The three for a
  # receiver using authentication wait for authentication in sessions.
  # A Your Discriminator of no session is counted by the daemon, since
  # it names no session.
  def counted(finding)
    to_sim.counters[:discards][finding] + @a.counters[:no_session][finding]
  end

  def test_every_fault_is_counted
    peer
    run_to(2.0)
    Fault.catalog.select { _1[:auth] == :none }.each do |e|
      before = counted(e[:finding])
      answer = @sim.act('fault', 'case' => e[:name].to_s)
      assert_equal [e[:finding], e[:expect]], answer.values_at(:finding, :expect)
      run_to(@clock.now + 0.01)
      counted = counted(e[:finding]) - before
      assert_equal e[:expect] == :discard ? 1 : 0, counted, e[:name].to_s
    end
    assert_equal Fault.catalog.count { _1[:auth] == :none }, @sim.sent[:fault].values.sum
    run_to(@clock.now + 3.0)
    assert_equal :up, to_sim.session.session_state
  end
end
