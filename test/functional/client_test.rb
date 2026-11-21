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
require 'tempfile'
require 'stringio'
require 'json'
require 'bfd4r'
require 'bfd/client'
require 'bfd/daemon/server'
require 'bfd/daemon/client'

# BFD::Client against two real bfdd4r over UDP on 127.0.0.1 and
# 127.0.0.2, in real time and without root, as programs_test.rb runs
# them. a is the router's bfdd4r; b is the peer's, with the session in
# its file.
class ClientProgram_Test < Test::Unit::TestCase
  A = '127.0.0.1'
  B = '127.0.0.2'

  def setup
    @tag = "bfd4r-client-#{Process.pid}-#{rand(1 << 30)}"
    @servers = {}
  end

  def teardown
    @bfd&.close
    @servers.each_key { |name| stop(name) }
  end

  def start(name, sessions = [])
    file = Tempfile.create(%w[bfdd4r .yml])
    file.write(JSON.generate('socket' => "@#{@tag}-#{name}", 'sessions' => sessions))
    file.close
    stop = Thread::Queue.new
    thread = Thread.new do
      BFD::Daemon::Server.new(StringIO.new, StringIO.new).start(['-f', file.path, '--log', File::NULL], {}, stop: stop)
    end
    @servers[name] = [stop, thread]
    control = BFD::Daemon::Client.new("@#{@tag}-#{name}")
    eventually { control.call('api.info') rescue nil }
    control
  ensure
    File.delete(file.path) if file
  end

  def stop(name)
    stop, thread = @servers.delete(name)
    return unless stop

    stop.push(:stop)
    thread.join(5)
  end

  def peer
    start('b', [{ 'interface' => 'lo', 'peer' => A, 'local' => B }])
  end

  def router
    start('a')
    @bfd = BFD::Client.new('isisd', socket: "@#{@tag}-a", retry_after: 0.1)
    @bfd.want(interface: 'lo', peer: B, local: A)
    @bfd
  end

  def now = Process.clock_gettime(Process::CLOCK_MONOTONIC)

  # Polls until the block is true of the events seen; answers them all.
  def until_seen(seconds = 5)
    seen = []
    deadline = now + seconds
    loop do
      IO.select(@bfd.ios, nil, nil, 0.05) unless @bfd.ios.empty?
      sleep 0.05 if @bfd.ios.empty?
      seen.concat(@bfd.poll(now))
      return seen if yield(seen)
      raise "timed out; seen: #{seen.map(&:to_h).inspect}" if now > deadline
    end
  end

  def eventually(seconds = 5)
    deadline = now + seconds
    loop do
      value = yield
      return value if value
      raise 'timed out' if now > deadline

      sleep 0.02
    end
  end

  def states(events) = events.select { _1.type == :state }.map(&:state)

  def test_a_session_comes_up
    peer
    router
    seen = until_seen { |s| s.any?(&:up?) }
    assert_equal :connected, seen.first.type
    assert_equal :up, states(seen).last
    assert_equal :up, @bfd.state(interface: 'lo', peer: B)
    refute seen.any?(&:failure?)
  end

  def test_the_session_is_asked_for_as_isisd
    peer
    a = router
    until_seen { |s| s.any?(&:up?) }
    control = BFD::Daemon::Client.new("@#{@tag}-a")
    assert_equal ['isisd'], control.call('show.sessions', 'interface' => 'lo', 'peer' => B).first['clients']
    a.drop(interface: 'lo', peer: B)
    a.poll(now)
    eventually { control.call('show.sessions').empty? }
  end

  # RFC 5882 4.2: the peer's AdminDown is not a failure.
  def test_the_peers_admin_down_is_not_a_failure
    b = peer
    router
    until_seen { |s| s.any?(&:up?) }
    b.call('session.admin', 'interface' => 'lo', 'peer' => A, 'down' => true)
    seen = until_seen { |s| states(s).include?(:admin_down) }
    refute seen.any?(&:failure?)
    b.call('session.admin', 'interface' => 'lo', 'peer' => A, 'down' => false)
    until_seen { |s| s.any?(&:up?) }
  end

  # The peer's bfdd4r stops without a word: the Detection Time expires.
  def test_a_silent_peer_is_a_failure
    peer
    router
    until_seen { |s| s.any?(&:up?) }
    stop('b')
    seen = until_seen(3) { |s| s.any?(&:failure?) }
    failure = seen.find(&:failure?)
    assert_equal ['lo', B, :up, :down, :control_detection_time_expired],
                 [failure.interface, failure.peer, failure.from, failure.state, failure.diag]
  end

  # The router's bfdd4r goes and comes back: told :lost, then the
  # session asked for again and Up.
  def test_bfdd4r_restarted
    peer
    router
    until_seen { |s| s.any?(&:up?) }
    stop('a')
    lost = until_seen { |s| s.any? { _1.type == :lost } }
    assert_equal [:lost], lost.map(&:type)
    assert_nil @bfd.state(interface: 'lo', peer: B)
    start('a')
    seen = until_seen { |s| s.any?(&:up?) }
    assert_equal :connected, seen.first.type
    refute seen.any?(&:failure?), 'a session asked for again is not a failure'
  end

  def test_a_refused_session_is_an_error
    router.want(interface: 'lo', peer: '127.0.0.3', local: A, desired_min_tx: 1000)
    seen = until_seen { |s| s.any? { _1.type == :error } }
    error = seen.find { _1.type == :error }
    assert_equal ['lo', '127.0.0.3'], [error.interface, error.peer]
    assert_match(/session.add: .*floor/, error.message)
  end
end
