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
require 'bfd/client'

# BFD::Client's rules that need no bfdd4r. The rest, against two real
# bfdd4r, is test/functional/client_test.rb.
class Client_Test < Test::Unit::TestCase
  E = BFD::Client::Event

  def nowhere
    BFD::Client.new('isisd', socket: "@bfd4r-nowhere-#{Process.pid}-#{rand(1 << 30)}", retry_after: 1.0)
  end

  # RFC 5882 4.2: Down because the peer is AdminDown is not a failure.
  def test_the_state_a_session_event_says
    assert_equal :up, BFD::Client.state_of('to' => 'up', 'remote_state' => 'up')
    assert_equal :down, BFD::Client.state_of('to' => 'down', 'remote_state' => 'down')
    assert_equal :down, BFD::Client.state_of('to' => 'down', 'remote_state' => 'up'),
                 'a Detection Time expired with the peer last Up'
    assert_equal :admin_down, BFD::Client.state_of('to' => 'down', 'remote_state' => 'admin_down')
    assert_equal :admin_down, BFD::Client.state_of('to' => 'admin_down', 'remote_state' => 'up')
  end

  def test_a_failure_is_up_to_down_only
    assert E.new(type: :state, from: :up, state: :down).failure?
    refute E.new(type: :state, from: :up, state: :admin_down).failure?, 'RFC 5882 4.2'
    refute E.new(type: :state, from: :init, state: :down).failure?, 'never Up'
    refute E.new(type: :state, from: nil, state: :down).failure?, 'the first state told'
    refute E.new(type: :lost).failure?
    assert E.new(type: :state, state: :up).up?
  end

  def test_no_bfdd4r_is_told_once_and_tried_again
    c = nowhere
    c.want(interface: 'eth1', peer: '10.0.0.2', local: '10.0.0.1')
    first = c.poll(0.0)
    assert_equal [:lost], first.map(&:type)
    assert_match(/no bfdd4r on @bfd4r-nowhere-/, first[0].message)
    assert_equal [], c.poll(0.5), 'not before retry'
    assert_equal [], c.poll(1.0), 'tried again, and not told again'
    refute c.connected?
    assert_equal [], c.ios
    assert c.wanted?(interface: 'eth1', peer: '10.0.0.2')
    assert_nil c.state(interface: 'eth1', peer: '10.0.0.2')
  end

  def test_the_socket_comes_from_the_environment
    assert_equal "\0bfdd4r", BFD::Client.new('isisd', env: {}).path
    assert_equal "\0other", BFD::Client.new('isisd', env: { 'BFD4R_SOCKET' => '@other' }).path
    assert_equal "\0mine", BFD::Client.new('isisd', socket: '@mine', env: { 'BFD4R_SOCKET' => '@other' }).path
  end

  def test_want_and_drop_while_away
    c = nowhere
    c.want(interface: 'eth1', peer: '10.0.0.2', local: '10.0.0.1', desired_min_tx: 300_000)
    c.drop(interface: 'eth1', peer: '10.0.0.2')
    refute c.wanted?(interface: 'eth1', peer: '10.0.0.2')
    assert_same c, c.drop(interface: 'eth1', peer: '10.0.0.9'), 'dropping what was never wanted is nothing'
  end
end
