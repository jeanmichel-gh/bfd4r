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
require 'tmpdir'
require 'open3'
require 'bfd4r'
require 'bfd/daemon/client'

# exe/with-bfdd4r, the router images' entrypoint: bfdd4r beside the
# command, started again when it fails, and one per namespace.
class WithBfdd4r_Test < Test::Unit::TestCase
  ROOT = File.expand_path('../..', __dir__)
  SCRIPT = File.join(ROOT, 'exe/with-bfdd4r')

  def setup
    @dir = Dir.mktmpdir('with-bfdd4r')
    @tag = "with-bfdd4r-#{Process.pid}-#{rand(1 << 30)}"
    @groups = []
  end

  def teardown
    @groups.each do |pgid|
      Process.kill('TERM', -pgid)
    rescue Errno::ESRCH
      nil
    end
    @groups.each do |pgid|
      Process.wait(pgid)
    rescue Errno::ECHILD
      nil
    end
    FileUtils.rm_rf(@dir)
  end

  def env(log) = { 'BFD4R_SOCKET' => "@#{@tag}", 'BFDD4R_LOG' => File.join(@dir, log) }

  # Runs with-bfdd4r around a shell that prints its pid and waits.
  def run_one(log)
    out = File.join(@dir, "#{log}.out")
    pid = Process.spawn(env(log), SCRIPT, 'sh', '-c', 'echo $$; exec sleep 60', out: out, pgroup: true)
    @groups << pid
    [pid, out]
  end

  def eventually(seconds = 10)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + seconds
    loop do
      value = yield
      return value if value
      raise 'timed out' if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline

      sleep 0.05
    end
  end

  def answers?
    BFD::Daemon::Client.new("@#{@tag}").call('api.info')
  rescue BFD::Daemon::Client::Error
    nil
  end

  def bfdd4r_pids(log)
    out, = Open3.capture2('pgrep', '-f', "bfdd4r --log #{File.join(@dir, log)}")
    out.split.map(&:to_i)
  end

  def test_the_command_runs_in_its_place_beside_bfdd4r
    pid, out = run_one('a.log')
    eventually { File.size?(out) }
    assert_equal pid, File.read(out).to_i, 'exec: the command keeps the pid, as PID 1 in a container'
    eventually { answers? }
  end

  def test_bfdd4r_is_started_again_when_it_fails
    run_one('a.log')
    eventually { answers? }
    first = bfdd4r_pids('a.log')
    assert_equal 1, first.size
    Process.kill('KILL', first[0])
    eventually { (now = bfdd4r_pids('a.log')).any? && now != first }
    eventually { answers? }
  end

  # bfd.md: a second bfdd4r in the namespace exits with 0, and is not
  # started again, so pe1 and pe1-bgp have one between them.
  def test_one_bfdd4r_in_a_namespace
    run_one('a.log')
    eventually { answers? }
    run_one('b.log')
    eventually { File.read(File.join(@dir, 'b.log')).include?('this one exits') rescue false }
    sleep 1.5
    assert_equal 1, File.read(File.join(@dir, 'b.log')).scan('this one exits').size, 'not started again'
    assert_equal [], bfdd4r_pids('b.log')
  end

  def test_no_command
    _out, err, status = Open3.capture3(SCRIPT)
    assert_equal 2, status.exitstatus
    assert_match(/usage: with-bfdd4r COMMAND/, err)
  end
end
