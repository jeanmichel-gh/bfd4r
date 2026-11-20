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
require_relative 'lab'

# bfdd4r against FRR's bfdd and BIRD, natively, in network namespaces,
# over IPv4 and IPv6, in real time (routescope docs/design/bfd.md,
# "Tests", the interop tier). Root.
#
#   sudo ruby test/interop/interop_test.rb
#
# Without root, FRR or BIRD a case omits, unless BFD4R_REQUIRE_FRR or
# BFD4R_REQUIRE_BIRD is set: then it fails. CI sets both.
module InteropCases
  def setup
    why = Lab.missing(peer)
    if why
      flunk(why) if ENV["BFD4R_REQUIRE_#{peer.upcase}"] == '1'
      omit(why)
    end
    @lab = Lab.new("bi#{peer}#{rand(1000)}").start(peer: peer)
    assert(@lab.wait_for(15) { both_up? }, "not up: ours #{states}, theirs #{@lab.theirs}\n#{@lab.log}")
  end

  def teardown
    @lab&.stop
  end

  def states
    @lab.ours.to_h { [_1['peer'], _1['state']] }
  end

  def both_up?
    states.values == %w[up up] && @lab.theirs.size == 2 && @lab.theirs.values.all?('up')
  end

  def diag(address)
    @lab.our(address)['variables']['bfd.LocalDiag']
  end

  # Up both ways on IPv4 and IPv6, at 300 ms x 3 both sides, TTL 255
  # received, nothing discarded.
  def test_up_on_ipv4_and_ipv6
    @lab.ours.each do |row|
      assert_equal [300_000, 900_000, {}], row.values_at('tx_interval', 'detection_time', 'discards'), row['peer']
      assert_equal 300_000, row['variables']['bfd.RemoteMinRxInterval']
      assert_not_equal 0, row['variables']['bfd.RemoteDiscr']
    end
    assert(@lab.wait_for(3) { @lab.ours.all? { _1['packets_in'] > 3 } })
    assert both_up?
  end

  # Stays Up: no flap over ten seconds.
  def test_stays_up
    sleep 10
    assert_equal [0, 0], @lab.ours.map { _1['flaps'] }
    assert both_up?
  end

  # RFC 5880 6.8.4: the link fails on the peer's side; we go Down with
  # diagnostic 1 within the Detection Time, and come back when it does.
  def test_link_down_and_back
    @lab.link(false)
    assert(@lab.wait_for(3) { states.values == %w[down down] })
    @lab.peers.each { assert_equal 1, diag(_1), _1 }
    @lab.link(true)
    assert(@lab.wait_for(15) { both_up? }, "ours #{states}, theirs #{@lab.theirs}")
  end

  # A netem loss of every packet the peer sends: caught here.
  def test_loss_toward_us
    @lab.loss(100)
    assert(@lab.wait_for(3) { states.values == %w[down down] })
    @lab.loss(0)
    assert(@lab.wait_for(15) { both_up? })
  end

  # RFC 5880 6.8.16: our AdminDown takes the peer Down, and back.
  def test_our_admin_down_reaches_the_peer
    @lab.peers.each { @lab.cli('session.admin', interface: Lab::IF, peer: _1, down: true) }
    assert(@lab.wait_for(5) { @lab.theirs.values.none?('up') }, @lab.theirs.inspect)
    @lab.peers.each { @lab.cli('session.admin', interface: Lab::IF, peer: _1, down: false) }
    assert(@lab.wait_for(15) { both_up? })
  end

  # RFC 5880 6.8.10 and 6.8.3: a new Required Min RX goes through a Poll
  # Sequence; the peer answers with Final and sends slower; the session
  # stays Up.
  def test_a_new_rx_interval
    @lab.cli('session.set', interface: Lab::IF, peer: Lab::PEER4, required_min_rx: 1_000_000)
    assert(@lab.wait_for(5) { !@lab.our(Lab::PEER4)['polling'] }, 'the Final came back')
    row = @lab.our(Lab::PEER4)
    assert_equal 3 * 1_000_000, row['detection_time']
    sleep 4
    assert_equal 0, @lab.our(Lab::PEER4)['flaps']
    assert both_up?
  end
end

class FrrInterop_Test < Test::Unit::TestCase
  include InteropCases

  def peer = :frr

  # FRR names its sessions' state and diagnostics itself; its view of
  # our AdminDown is "down" with the remote diagnostic.
  def test_frr_reads_our_admin_down
    @lab.cli('session.admin', interface: Lab::IF, peer: Lab::PEER4, down: true)
    assert(@lab.wait_for(5) { @lab.theirs[Lab::OURS4] == 'down' })
    peer = JSON.parse(@lab.frr('show bfd peers json')).find { _1['peer'] == Lab::OURS4 }
    assert_equal 'administratively down', peer['remote-diagnostic']
  end
end

class BirdInterop_Test < Test::Unit::TestCase
  include InteropCases

  def peer = :bird
end
