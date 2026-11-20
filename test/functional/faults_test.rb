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

# Each catalog entry sent into our session while it is Up with a
# correct peer, and counted: a :discard entry is discarded for its
# finding and changes nothing; a :record entry is accepted, and what the
# session did is written down. Later, bfd4r-sim sends the same into
# bfdd4r, FRR's bfdd and BIRD: the fault matrix.
class Faults_Test < Test::Unit::TestCase
  include BFD

  def up_pair
    r = Random.new(7)
    Pair.new(a: Session.new(local_discr: 1, random: r), b: Session.new(local_discr: 2, random: r)).start.run_until(1.0)
  end

  # What our session did with an entry: [its action, findings].
  def send_fault(pr, e)
    octets = Fault.wire(e[:name], my_discr: pr.b.local_discr, your_discr: pr.a.local_discr)
    out = pr.a.receive(octets, pr.clock.now, ttl: e[:ttl], payload: octets.bytesize)
    discard = out.grep(Session::Discard).first
    [discard ? :discard : :accept, discard ? discard.findings.map(&:name) : []]
  end

  # The entries for a receiver with authentication in use wait for
  # authentication in sessions.
  def entries
    Fault.catalog.reject { _1[:auth] == :sha1 }
  end

  def test_the_entries_left_for_authentication
    assert_equal %i[auth_failed auth_missing short_auth], Fault.catalog.select { _1[:auth] == :sha1 }.map { _1[:name] }.sort
  end

  def test_every_discard_entry_is_discarded_and_changes_nothing
    counts = Hash.new(0)
    entries.select { _1[:expect] == :discard }.each do |e|
      pr = up_pair
      before = pr.a.variables
      verdict, findings = send_fault(pr, e)
      assert_equal [:discard, [e[:finding]]], [verdict, findings], e[:name].to_s
      assert_equal before, pr.a.variables, e[:name].to_s
      counts[findings.first] += 1
      pr.run_for(2.0)
      assert_equal :up, pr.a.session_state, e[:name].to_s
    end
    assert_equal 11, counts.values.sum, "sixteen entries, less three for authentication and two to record"
  end

  # The RFCs leave these open. What our session does, recorded:
  # poll_and_final ends our Poll Sequence if one runs and is answered
  # with Final; desired_min_tx_zero is taken as the peer's Desired Min
  # TX, so our Detection Time uses our own Required Min RX.
  def test_the_record_entries_are_accepted
    pr = up_pair
    pr.call(pr.a) { |s, now| s.set(now, desired_min_tx: 200_000) }
    assert pr.a.polling?
    e = Fault.entry(:poll_and_final)
    octets = Fault.wire(:poll_and_final, my_discr: 2, your_discr: 1)
    out = pr.a.receive(octets, pr.clock.now, ttl: e[:ttl])
    refute pr.a.polling?, 'the F bit ended our Poll Sequence'
    assert_equal [true], out.grep(Session::Send).map { _1.packet.final? }, 'the P bit was answered'

    pr = up_pair
    assert_equal :accept, send_fault(pr, Fault.entry(:desired_min_tx_zero))[0]
    assert_equal [0, 3 * 300_000], [pr.a.remote_desired_min_tx, pr.a.detection_time]
  end
end
