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
require 'open3'
require 'json'
require 'stringio'
require 'socket'
require 'bfd4r'
require 'bfd/daemon/server'
require 'bfd/daemon/client'

# Two bfdd4r, each in a thread of this process, over real UDP on
# 127.0.0.1 and 127.0.0.2, and driven through their sockets as
# bfd4r-cli and the routers drive them. Real time: a session comes Up in
# milliseconds and goes Down in 0.9 s. No root: the sockets bind
# addresses, not interfaces. IPv6 needs two addresses of its own, so it
# is the interop tier's (step 4c), in network namespaces.
class Programs_Test < Test::Unit::TestCase
  include BFD::Daemon

  A = '127.0.0.1'
  B = '127.0.0.2'
  ROOT = File.expand_path('../..', __dir__)

  def setup
    @tag = "bfdd4r-test-#{Process.pid}-#{rand(1 << 30)}"
    @servers = []
  end

  def teardown
    @servers.each do |stop, thread|
      stop.push(:stop)
      thread.join(5)
    end
  end

  # A bfdd4r with a file of sessions; answers its client.
  def daemon(name, sessions, **top)
    file = Tempfile.create(%w[bfdd4r .yml])
    file.write(JSON.generate({ 'socket' => "@#{@tag}-#{name}", 'sessions' => sessions }.merge(top.transform_keys(&:to_s))))
    file.close
    stop = Thread::Queue.new
    err = StringIO.new
    thread = Thread.new { Server.new(StringIO.new, err).start(['-f', file.path, '--log', File::NULL], {}, stop: stop) }
    @servers << [stop, thread]
    client = Client.new("@#{@tag}-#{name}")
    eventually { client.call('api.info') rescue nil }
    client
  ensure
    File.delete(file.path) if file
  end

  def pair
    a = daemon('a', [{ 'interface' => 'lo', 'peer' => B, 'local' => A }])
    b = daemon('b', [{ 'interface' => 'lo', 'peer' => A, 'local' => B }])
    [a, b]
  end

  def state(client, peer)
    client.call('show.sessions', 'interface' => 'lo', 'peer' => peer).first
  end

  def eventually(seconds = 5)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + seconds
    loop do
      value = yield
      return value if value
      raise 'timed out' if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline

      sleep 0.02
    end
  end

  def test_two_bfdd4r_come_up_over_udp
    a, b = pair
    eventually { state(a, B)['state'] == 'up' && state(b, A)['state'] == 'up' }
    row = state(a, B)
    assert_equal [['file'], 300_000, 900_000], row.values_at('clients', 'tx_interval', 'detection_time')
    assert_equal({}, row['discards'], 'TTL 255 came, and nothing was discarded')
  end

  # docs/timing.md: 300 ms by default; the file may lower it.
  def test_the_floor_comes_from_the_file
    key = { 'interface' => 'lo', 'peer' => B, 'local' => A, 'client' => 'isisd', 'desired_min_tx' => 100_000 }
    plain = daemon('plain', [])
    e = assert_raise(Client::Error) { plain.call('session.add', key) }
    assert_match(/under the floor of 300000/, e.message)
    lowered = daemon('lowered', [], floor: 100_000)
    assert_equal ['isisd'], lowered.call('session.add', key)['clients']
  end

  def test_admin_down_goes_across
    a, b = pair
    eventually { state(a, B)['state'] == 'up' }
    b.call('session.admin', 'interface' => 'lo', 'peer' => A, 'down' => true)
    eventually { state(a, B)['state'] == 'down' }
    assert_equal 3, state(a, B)['variables']['bfd.LocalDiag']
    b.call('session.admin', 'interface' => 'lo', 'peer' => A, 'down' => false)
    eventually { state(a, B)['state'] == 'up' }
  end

  def test_the_detection_time
    a, b = pair
    eventually { state(a, B)['state'] == 'up' }
    b.call('session.delete', 'interface' => 'lo', 'peer' => A, 'client' => 'file')
    eventually { state(a, B)['state'] == 'down' }
    assert_equal 3, state(a, B)['variables']['bfd.LocalDiag'], 'AdminDown was sent before it went'
    eventually(3) { b.call('show.sessions').empty? }
  end

  # RFC 5881 5: a TTL other than 255 is discarded and counted.
  def test_a_packet_with_ttl_254_is_discarded
    a, = pair
    eventually { state(a, B)['state'] == 'up' }
    row = state(a, B)
    sock = Socket.new(:INET, :DGRAM)
    sock.setsockopt(Socket::IPPROTO_IP, Socket::IP_TTL, 254)
    sock.bind(Addrinfo.udp(B, 0))
    packet = BFD::Control.new(state: :up, my_discr: row['variables']['bfd.RemoteDiscr'],
                              your_discr: row['variables']['bfd.LocalDiscr'], desired_min_tx: 300_000,
                              required_min_rx: 300_000)
    sock.send(packet.encode, 0, Addrinfo.udp(A, 3784))
    sock.close
    eventually { state(a, B)['discards'] == { 'ttl_not_255' => 1 } }
  end

  def test_a_client_shares_the_file_session
    a, = pair
    a.call('session.add', 'interface' => 'lo', 'peer' => B, 'local' => A, 'client' => 'isisd')
    assert_equal %w[file isisd], state(a, B)['clients']
    a.call('session.delete', 'interface' => 'lo', 'peer' => B, 'client' => 'file')
    assert_equal %w[isisd], state(a, B)['clients']
  end

  def test_the_event_stream
    a, b = pair
    eventually { state(a, B)['state'] == 'up' }
    lines = []
    reader = Thread.new do
      Client.new("@#{@tag}-a").stream('events.subscribe', 'kinds' => ['session']) do |line|
        lines << line
        !(line['event'] && line['event']['data']['to'] == 'down')
      end
    end
    eventually { lines.any? }
    b.call('session.admin', 'interface' => 'lo', 'peer' => A, 'down' => true)
    reader.join(5)
    event = lines.find { _1['event'] }['event']
    assert_equal ['session', "lo #{B}", 'warn'], event.values_at('kind', 'session', 'level')
    assert_equal({ 'from' => 'up', 'to' => 'down', 'diag' => 'neighbor_signaled_session_down',
                   'interface' => 'lo', 'peer' => B }, event['data'])
    assert_match(/\A\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z\z/, event['time'])
  end

  # One bfdd4r per namespace: the second finds the socket in use and
  # exits with 0, as an image that starts it always needs.
  def test_a_second_bfdd4r_exits_quietly
    daemon('a', [])
    out, err, status = Open3.capture3(RbConfig.ruby, File.join(ROOT, 'exe/bfdd4r'), '-s', "@#{@tag}-a")
    assert_equal [0, ''], [status.exitstatus, out]
    assert_match(/another bfdd4r answers on @#{@tag}-a; this one exits/, err)
  end

  def test_bfd4r_cli_as_a_program
    a, = pair
    eventually { state(a, B)['state'] == 'up' }
    out, _err, status = Open3.capture3(RbConfig.ruby, File.join(ROOT, 'exe/bfd4r-cli'), '-s', "@#{@tag}-a",
                                       'show.sessions')
    assert_equal 0, status.exitstatus
    assert_equal 'up', JSON.parse(out)[0]['state']
    out, = Open3.capture3(RbConfig.ruby, File.join(ROOT, 'exe/bfdd4r'), '--version')
    assert_equal "#{BFD::VERSION}\n", out
  end

  def test_a_bad_file_stops_bfdd4r
    Tempfile.create(%w[bfdd4r .yml]) do |f|
      f.write("sesions: []\n")
      f.flush
      _out, err, status = Open3.capture3(RbConfig.ruby, File.join(ROOT, 'exe/bfdd4r'), '-f', f.path,
                                         '-s', "@#{@tag}-bad")
      assert_equal [1, "bfdd4r: unknown key sesions\n"], [status.exitstatus, err]
    end
  end
end
