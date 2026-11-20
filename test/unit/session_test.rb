require 'test/unit'
require 'bfd/session'
require_relative '../support/pair'

# BFD::Session against RFC 5880 6.8, on a manual clock: the variables of
# 6.8.1, every transition of 6.8.6, the timers of 6.8.3, 6.8.4 and 6.8.7,
# the jitter and the Poll Sequence (6.5).
class Session_Test < Test::Unit::TestCase
  include BFD

  def session(**opts)
    Session.new(local_discr: 7, random: Random.new(1), **opts)
  end

  # A packet from the remote end, discriminator 9, as BIRD sends at
  # 300 ms x 3.
  def from_peer(state, **fields)
    Control.new({ state: state, my_discr: 9, your_discr: state == :down || state == :admin_down ? 0 : 7,
                  desired_min_tx: 300_000, required_min_rx: 300_000 }.merge(fields))
  end

  def sends(actions)
    actions.grep(Session::Send).map(&:packet)
  end

  def changes(actions)
    actions.grep(Session::StateChange).map { [_1.from, _1.to, _1.diag] }
  end

  # A session brought to state, at time 0.
  def in_state(state, **opts)
    s = session(**opts)
    s.start(0.0)
    case state
    when :init then s.receive(from_peer(:down), 0.0)
    when :up then s.receive(from_peer(:init), 0.0)
    when :admin_down then s.admin_down(0.0)
    end
    assert_equal state, s.session_state
    s
  end

  # 6.8.1: the initial values.

  def test_the_variables_start_as_6_8_1_says
    s = session(desired_min_tx: 300_000, required_min_rx: 200_000, detect_mult: 4)
    assert_equal({ 'bfd.SessionState' => :down, 'bfd.RemoteSessionState' => :down, 'bfd.LocalDiscr' => 7,
                   'bfd.RemoteDiscr' => 0, 'bfd.LocalDiag' => 0, 'bfd.DesiredMinTxInterval' => 1_000_000,
                   'bfd.RequiredMinRxInterval' => 200_000, 'bfd.RemoteMinRxInterval' => 1,
                   'bfd.DemandMode' => 0, 'bfd.RemoteDemandMode' => 0, 'bfd.DetectMult' => 4,
                   'bfd.AuthType' => 0 }, s.variables)
  end

  def test_a_random_nonzero_local_discriminator
    discrs = Array.new(50) { |i| Session.new(random: Random.new(i)).local_discr }
    assert(discrs.all? { _1.between?(1, 0xffff_ffff) })
    assert_operator discrs.uniq.size, :>, 45
    assert_raise(ArgumentError) { Session.new(local_discr: 0) }
    assert_raise(ArgumentError) { Session.new(local_discr: 1, detect_mult: 0) }
  end

  # 6.8.6: what is set from every packet that is not discarded.

  def test_a_packet_sets_the_remote_variables
    s = in_state(:down)
    s.receive(from_peer(:down, required_min_rx: 50_000, demand: true, detect_mult: 5, desired_min_tx: 400_000), 1.0)
    assert_equal [9, :down, 1, 50_000], [s.remote_discr, s.remote_session_state, s.remote_demand_mode, s.remote_min_rx_interval]
    assert_equal [5, 400_000], [s.remote_detect_mult, s.remote_desired_min_tx]
  end

  # 6.8.6: the state machine, every local state against every received
  # state. Each row: local, received => new state, diagnostic.
  TRANSITIONS = {
    %i[down admin_down] => [:down, :none],
    %i[down down] => [:init, :none],
    %i[down init] => [:up, :none],
    %i[down up] => [:down, :none],
    %i[init admin_down] => [:down, :neighbor_signaled_session_down],
    %i[init down] => [:init, :none],
    %i[init init] => [:up, :none],
    %i[init up] => [:up, :none],
    %i[up admin_down] => [:down, :neighbor_signaled_session_down],
    %i[up down] => [:down, :neighbor_signaled_session_down],
    %i[up init] => [:up, :none],
    %i[up up] => [:up, :none],
    %i[admin_down admin_down] => [:admin_down, :administratively_down],
    %i[admin_down down] => [:admin_down, :administratively_down],
    %i[admin_down init] => [:admin_down, :administratively_down],
    %i[admin_down up] => [:admin_down, :administratively_down]
  }.freeze

  def test_every_transition_of_6_8_6
    TRANSITIONS.each do |(local, received), (state, diag)|
      s = in_state(local)
      out = s.receive(from_peer(received), 1.0)
      assert_equal [state, diag], [s.session_state, Control::DIAGS[s.local_diag]], "#{local} receives #{received}"
      if state == local
        assert_equal [], changes(out), "#{local} receives #{received}"
      else
        assert_equal [[local, state, diag]], changes(out)
        # 6.8.7: the new state goes out at once.
        assert_equal state, sends(out).last.state_name
      end
    end
  end

  def test_every_pair_is_in_the_table
    assert_equal 16, TRANSITIONS.size
  end

  def test_admin_down_discards_without_a_final
    s = in_state(:admin_down)
    assert_equal [], s.receive(from_peer(:up, poll: true), 1.0)
    assert_equal 9, s.remote_discr, 'the variables are set before the discard'
  end

  # The discard rules: nothing changes, and the packet does not count.

  def test_a_discarded_packet_changes_nothing
    s = in_state(:init)
    detect_at = s.detect_at
    out = s.receive(from_peer(:init, detect_mult: 0), 0.5)
    assert_equal [Session::Discard], out.map(&:class)
    assert_equal [:detect_mult_zero], out[0].findings.map(&:name)
    assert_equal [:init, detect_at], [s.session_state, s.detect_at]
  end

  def test_an_unknown_your_discriminator_is_discarded
    out = in_state(:init).receive(from_peer(:init, your_discr: 8), 0.5)
    assert_equal [:your_discr_unknown], out[0].findings.map(&:name)
  end

  def test_a_ttl_other_than_255_is_discarded
    out = in_state(:init).receive(from_peer(:init), 0.5, ttl: 254)
    assert_equal [:ttl_not_255], out[0].findings.map(&:name)
  end

  def test_octets_are_read
    s = in_state(:down)
    s.receive(from_peer(:down).encode, 0.5)
    assert_equal :init, s.session_state
  end

  # 6.8.4: the Detection Time.

  def test_the_detection_time
    s = in_state(:down, required_min_rx: 200_000)
    s.receive(from_peer(:down, detect_mult: 4, desired_min_tx: 250_000), 1.0)
    assert_equal 4 * 250_000, s.detection_time
    s.receive(from_peer(:init, detect_mult: 2, desired_min_tx: 100_000), 1.5)
    assert_equal 2 * 200_000, s.detection_time, 'the greater of RequiredMinRx and the remote Desired Min TX'
    assert_in_delta 1.9, s.detect_at, 1e-9
  end

  def test_up_goes_down_when_the_detection_time_passes
    s = in_state(:up)
    s.receive(from_peer(:up), 1.0)
    assert_equal [], changes(s.tick(1.899))
    out = s.tick(1.9)
    assert_equal [[:up, :down, :control_detection_time_expired]], changes(out)
    assert_equal [:down, 1], [sends(out).last.state_name, sends(out).last.diag]
  end

  def test_init_goes_down_when_the_detection_time_passes
    s = in_state(:init)
    assert_equal [[:init, :down, :control_detection_time_expired]], changes(s.tick(0.9))
  end

  def test_down_stays_down_when_the_detection_time_passes
    s = in_state(:down)
    s.receive(from_peer(:up), 0.0)
    assert_equal [], changes(s.tick(1.0))
  end

  def test_admin_down_stays_when_the_detection_time_passes
    s = in_state(:admin_down)
    s.receive(from_peer(:up), 0.0)
    assert_equal [], changes(s.tick(1.0))
  end

  # 6.8.1: bfd.RemoteDiscr is zeroed after a Detection Time without a
  # packet, in any state.
  def test_the_remote_discriminator_is_forgotten
    s = in_state(:down)
    s.receive(from_peer(:up), 0.0)
    s.tick(0.899)
    assert_equal 9, s.remote_discr
    s.tick(0.9)
    assert_equal 0, s.remote_discr
  end

  # 6.8.3: no faster than one a second while not Up.

  def test_one_second_while_not_up
    s = in_state(:down, desired_min_tx: 50_000)
    assert_equal 1_000_000, sends(s.tick(s.next_due)).last.desired_min_tx
    s.receive(from_peer(:init), 1.0)
    assert_equal 50_000, s.build.desired_min_tx
    s.tick(5.0)
    assert_equal :down, s.session_state
    assert_equal 1_000_000, s.build.desired_min_tx
  end

  # 6.8.7: the transmit interval and the jitter.

  def test_the_interval_is_the_greater_of_ours_and_theirs
    s = in_state(:up, desired_min_tx: 300_000)
    s.receive(from_peer(:up, final: true, required_min_rx: 500_000), 0.0)
    assert_equal 500_000, s.tx_interval
    s.receive(from_peer(:up, required_min_rx: 100_000), 0.1)
    assert_equal 300_000, s.tx_interval
  end

  def intervals(s, count)
    now = s.last_rx
    s.tick(now)
    Array.new(count) do
      due = s.next_tx
      s.receive(from_peer(:up), due) # keep the session Up
      s.tick(due)
      gap = due - now
      now = due
      gap
    end
  end

  def test_the_jitter_cuts_0_to_25_percent
    s = in_state(:up)
    s.receive(from_peer(:up, final: true), 0.0)
    gaps = intervals(s, 2000).map { _1 / 0.3 }
    assert(gaps.all? { _1.between?(0.75, 1.0) }, "#{gaps.minmax}")
    assert_in_delta 0.875, gaps.sum / gaps.size, 0.01
    assert_operator gaps.min, :<, 0.76
    assert_operator gaps.max, :>, 0.99
  end

  def test_with_detect_mult_1_between_75_and_90_percent
    s = in_state(:up, detect_mult: 1)
    s.receive(from_peer(:up, final: true), 0.0)
    gaps = intervals(s, 2000).map { _1 / 0.3 }
    assert(gaps.all? { _1.between?(0.75, 0.9 + 1e-9) }, "#{gaps.minmax}")
  end

  # 6.8.3: coming Up shortens our interval from 1 s, and the next packet
  # is pulled in rather than sent on the old schedule.
  def test_a_shorter_own_interval_is_used_at_once
    s = in_state(:init, desired_min_tx: 300_000)
    assert_operator s.next_tx, :>, 0.7
    s.receive(from_peer(:up), 0.05)
    assert_operator s.next_tx, :<=, 0.05 + 0.3
  end

  def test_no_periodic_packets_when_the_remote_wants_none
    s = in_state(:up)
    s.receive(from_peer(:up, required_min_rx: 0), 0.0)
    assert_equal s.detect_at, s.next_due, 'only the Detection Time is due'
    assert_equal [], sends(s.tick(0.8))
  end

  def test_the_passive_role_waits_for_the_remote
    s = session(passive: true)
    assert_equal [], s.start(0.0)
    assert_nil s.next_due
    s.receive(from_peer(:down), 1.0)
    assert_equal :init, s.session_state
    assert_operator s.next_due, :<=, 2.0
  end

  def test_no_periodic_packets_while_the_remote_is_in_demand_mode
    s = in_state(:up)
    s.receive(from_peer(:up, final: true, demand: true), 0.0)
    refute s.polling?
    assert_equal [], sends(s.tick(0.5))
  end

  def test_a_reduced_remote_min_rx_is_honoured_at_once
    s = in_state(:up, desired_min_tx: 50_000)
    s.receive(from_peer(:up, final: true, required_min_rx: 2_000_000), 0.0)
    sent = s.next_tx
    s.tick(sent)
    assert_operator s.next_tx - sent, :>, 1.4
    s.receive(from_peer(:up, required_min_rx: 50_000), sent + 0.01)
    assert_operator s.next_tx, :<=, sent + 0.05
  end

  # 6.5 and 6.8.7: Poll and Final.

  def test_a_poll_is_answered_with_final_at_once
    s = in_state(:up)
    s.receive(from_peer(:up, final: true), 0.0)
    out = s.receive(from_peer(:up, poll: true), 0.1)
    assert_equal 1, sends(out).size
    assert(sends(out)[0].final? && !sends(out)[0].poll?)
  end

  def test_a_poll_that_changes_the_state_gets_one_packet_with_final
    s = in_state(:down)
    out = s.receive(from_peer(:init, poll: true), 0.0)
    assert_equal [[:up, true, false]], sends(out).map { [_1.state_name, _1.final?, _1.poll?] }
  end

  def test_coming_up_starts_a_poll_sequence
    s = in_state(:init, desired_min_tx: 300_000)
    out = s.receive(from_peer(:up), 0.0)
    assert s.polling?
    assert sends(out).last.poll?, 'BIRD and FRR also send Up with Poll'
    assert sends(s.tick(s.next_due)).last.poll?, 'the Poll goes on the periodic packets'
    s.receive(from_peer(:up, final: true), 0.5)
    refute s.polling?
    refute sends(s.tick(s.next_due)).last.poll?
  end

  def test_a_poll_sequence_sends_no_extra_packets
    s = in_state(:up)
    s.receive(from_peer(:up, final: true), 0.0)
    assert_equal [], sends(s.set(0.1, desired_min_tx: 200_000))
    assert s.polling?
  end

  def test_never_poll_and_final_together
    s = in_state(:init)
    s.receive(from_peer(:up), 0.0)
    assert s.polling?
    packets = sends(s.receive(from_peer(:up, poll: true), 0.1))
    assert(packets.none? { _1.poll? && _1.final? })
  end

  # 6.8.3: an increase of Desired Min TX while Up waits for the Final.
  def test_a_slower_tx_waits_for_the_final
    s = in_state(:up, desired_min_tx: 300_000)
    s.receive(from_peer(:up, final: true), 0.0)
    s.set(0.1, desired_min_tx: 1_000_000)
    assert_equal [1_000_000, 300_000], [s.desired_min_tx_interval, s.tx_interval]
    assert_equal 1_000_000, s.build.desired_min_tx, 'the new value goes out'
    s.receive(from_peer(:up, final: true), 0.2)
    assert_equal 1_000_000, s.tx_interval
  end

  def test_a_faster_tx_is_used_at_once
    s = in_state(:up, desired_min_tx: 300_000)
    s.receive(from_peer(:up, final: true, required_min_rx: 50_000), 0.0)
    s.set(0.1, desired_min_tx: 100_000)
    assert_equal 100_000, s.tx_interval
  end

  # 6.8.3: a reduction of Required Min RX while Up is not used for the
  # Detection Time until the Final.
  def test_a_shorter_detection_waits_for_the_final
    s = in_state(:up, required_min_rx: 300_000)
    s.receive(from_peer(:up, final: true, desired_min_tx: 50_000), 0.0)
    s.set(0.1, required_min_rx: 100_000)
    assert_equal 100_000, s.build.required_min_rx
    assert_equal 3 * 300_000, s.detection_time
    s.receive(from_peer(:up, final: true, desired_min_tx: 50_000), 0.2)
    assert_equal 3 * 100_000, s.detection_time
  end

  def test_a_longer_detection_is_used_at_once
    s = in_state(:up, required_min_rx: 300_000)
    s.receive(from_peer(:up, final: true), 0.0)
    s.set(0.1, required_min_rx: 1_000_000)
    assert_equal 3 * 1_000_000, s.detection_time
    assert_in_delta 3.0, s.detect_at, 1e-9
  end

  # 6.8.3, choice 3: a second change waits for the first Poll Sequence to
  # end and for one more packet with Final clear.
  def test_a_second_change_waits_for_the_first_poll
    s = in_state(:up)
    s.receive(from_peer(:up, final: true), 0.0)
    s.set(0.1, desired_min_tx: 200_000)
    s.set(0.2, required_min_rx: 200_000)
    s.receive(from_peer(:up, final: true), 0.3)
    refute s.polling?, 'the first sequence ended'
    s.receive(from_peer(:up), 0.4)
    assert s.polling?, 'the second starts after a packet with F clear'
  end

  def test_detect_mult_needs_no_poll
    s = in_state(:up)
    s.receive(from_peer(:up, final: true), 0.0)
    s.set(0.1, detect_mult: 5)
    refute s.polling?
    assert_equal 5, s.build.detect_mult
    assert_raise(ArgumentError) { s.set(0.1, detect_mult: 0) }
  end

  # 6.8.16: administrative control.

  def test_admin_down_and_back
    s = in_state(:up)
    out = s.admin_down(1.0)
    assert_equal [[:up, :admin_down, :administratively_down]], changes(out)
    assert_equal [:admin_down, 7], [sends(out).last.state_name, sends(out).last.diag]
    assert_operator s.tick(s.next_tx).grep(Session::Send).size, :>, 0, 'AdminDown keeps being sent (6.8.16 MAY)'
    assert_equal [[:admin_down, :down, :administratively_down]], changes(s.enable(2.0))
  end

  def test_admin_down_with_path_down
    s = in_state(:up)
    s.admin_down(1.0, diag: :path_down)
    assert_equal 5, s.local_diag
  end

  def test_the_packet_follows_6_8_7
    s = in_state(:up, desired_min_tx: 300_000, required_min_rx: 200_000, detect_mult: 4)
    p = s.build
    assert_equal [1, :up, 4, 24, 7, 9, 300_000, 200_000, 0],
                 [p.version, p.state_name, p.detect_mult, p.length, p.my_discr, p.your_discr,
                  p.desired_min_tx, p.required_min_rx, p.required_min_echo_rx]
    refute p.multipoint? || p.demand? || p.auth_present? || p.cpi?
    assert_equal [], p.errors
  end

  # Two sessions on one manual clock, as bfdd4r runs them.

  def pair(start: true)
    r = Random.new(3)
    pr = Pair.new(a: Session.new(local_discr: 1, random: r), b: Session.new(local_discr: 2, random: r))
    start ? pr.start : pr
  end

  def test_two_sessions_come_up
    pr = pair.run_until(0.01)
    assert_equal %i[up up], [pr.a.session_state, pr.b.session_state]
    assert_equal [[:down, :init], [:init, :up]], pr.changes(pr.a).map { [_1.action.from, _1.action.to] }
    pr.run_until(5.0)
    refute pr.a.polling? || pr.b.polling?
    assert_equal [300_000, 300_000], [pr.a.tx_interval, pr.b.tx_interval]
    assert_equal [], pr.changes.select { _1.time > 0.01 }
    assert(pr.sent.none? { _1.action.packet.poll? && _1.action.packet.final? })
  end

  def test_a_lost_direction_is_caught_within_the_detection_time
    pr = pair.run_until(2.0)
    pr.cut(pr.b)
    pr.run_until(4.0)
    down = pr.changes(pr.a).find { _1.action.to == :down }
    assert_equal :control_detection_time_expired, down.action.diag
    assert_operator down.time - 2.0, :<=, 0.9
    b_down = pr.changes(pr.b).find { _1.action.to == :down }
    assert_equal :neighbor_signaled_session_down, b_down.action.diag
  end

  def test_admin_down_takes_the_other_end_down_and_back
    pr = pair.run_until(1.0)
    pr.call(pr.a) { |s, now| s.admin_down(now) }
    pr.run_until(2.0)
    assert_equal %i[admin_down down], [pr.a.session_state, pr.b.session_state]
    assert_equal 3, pr.b.local_diag
    pr.call(pr.a) { |s, now| s.enable(now) }
    pr.run_until(5.0)
    assert_equal %i[up up], [pr.a.session_state, pr.b.session_state]
  end

  def test_the_pace_while_down_is_one_a_second
    pr = pair(start: false)
    pr.cut(pr.b)
    pr.start.run_until(10.0)
    assert_equal :down, pr.a.session_state
    times = pr.sent(pr.a).map(&:time)
    gaps = times.each_cons(2).map { _2 - _1 }
    assert(gaps.all? { _1.between?(0.75, 1.0) }, gaps.inspect)
  end
end
