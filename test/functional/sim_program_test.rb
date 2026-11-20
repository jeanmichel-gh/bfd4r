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
require 'json'
require 'net/http'
require 'tempfile'
require 'stringio'
require 'bfd/daemon/server'
require 'bfd/daemon/client'
require 'bfd/sim/server'

# bfd4r-sim and bfdd4r as programs, each in a thread of this process,
# over real UDP on 127.0.0.1 (bfdd4r) and 127.0.0.2 (the sim). The sim
# is driven over HTTP, as routescope will drive it. No root.
class SimProgram_Test < Test::Unit::TestCase
  include BFD

  D = '127.0.0.1'
  S = '127.0.0.2'

  def setup
    @tag = "bfd4r-sim-test-#{Process.pid}-#{rand(1 << 30)}"
    @stops = []
    @threads = []
    @files = []
    @bfdd = daemon
    @api = sim
  end

  def teardown
    @stops.each { _1.push(:stop) }
    @threads.each { _1.join(5) }
    @files.each { File.delete(_1) if File.exist?(_1) }
  end

  def file(hash)
    f = Tempfile.create(%w[bfd4r .yml])
    f.write(JSON.generate(hash))
    f.close
    @files << f.path
    f.path
  end

  def daemon
    path = file('socket' => "@#{@tag}", 'sessions' => [{ 'interface' => 'lo', 'peer' => S, 'local' => D }])
    stop = Thread::Queue.new
    @stops << stop
    @threads << Thread.new { Daemon::Server.new(StringIO.new, StringIO.new).start(['-f', path, '--log', File::NULL], {}, stop: stop) }
    client = Daemon::Client.new("@#{@tag}")
    eventually { client.call('api.info') rescue nil }
    client
  end

  def sim
    path = file('local' => S, 'api' => '127.0.0.1:0')
    stop = Thread::Queue.new
    started = Thread::Queue.new
    err = StringIO.new
    @stops << stop
    @threads << Thread.new do
      Sim::Server.new(StringIO.new, err).start(['-f', path, '--log', File::NULL], stop: stop,
                                                                              on_start: ->(http) { started.push(http.port) })
    end
    port = started.pop(timeout: 5) or flunk("bfd4r-sim did not start: #{err.string}")
    "http://127.0.0.1:#{port}"
  end

  def get(path)
    JSON.parse(Net::HTTP.get(URI("#{@api}#{path}")))
  end

  def post(path, body, header: true)
    h = { 'Content-Type' => 'application/json' }
    h['X-BFD4R'] = 'routescope' if header
    r = Net::HTTP.post(URI("#{@api}#{path}"), JSON.generate(body), h)
    [r.code.to_i, JSON.parse(r.body)]
  end

  def row = @bfdd.call('show.sessions', 'interface' => 'lo', 'peer' => S).first

  def eventually(seconds = 5)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + seconds
    loop do
      value = yield
      return value if value
      raise 'timed out' if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline

      sleep 0.02
    end
  end

  def test_a_peer_session_comes_up_and_a_fault_is_counted
    assert_equal 403, post('/api/peer', { 'to' => D }, header: false)[0]
    code, peer = post('/api/peer', { 'to' => D })
    assert_equal [200, D], [code, peer['to']]
    eventually { row['state'] == 'up' && get('/api/status')['peer']['state'] == 'up' }
    code, fault = post('/api/fault', { 'case' => 'ttl_254' })
    assert_equal [200, 'ttl_not_255'], [code, fault['finding']]
    eventually { row['discards'] == { 'ttl_not_255' => 1 } }
    assert_operator get('/api/received')['from_peer'], :>, 0
  end

  # RFC 5880 6.8.6 and RFC 5882 4.2: AdminDown takes bfdd4r Down with
  # diagnostic 3.
  def test_a_behaviour_over_udp
    post('/api/peer', { 'to' => D, 'behaviour' => 'admin_down', 'after' => 0.3 })
    eventually { row['state'] == 'down' && row['flaps'] == 1 }
    assert_equal 3, row['variables']['bfd.LocalDiag']
    assert_equal 'session', post('/api/stop', {})[1]['stopped']
    assert_nil get('/api/status')['peer']
  end
end
