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
require 'fileutils'
require 'json'
require 'open3'
require 'rbconfig'
require 'tmpdir'

# bfdd4r in two VRFs that hold the same addresses, as pe1 in bgp4r's
# l3vpn-lab (routescope docs/design/bfd-vrf.md). Root.
#
#   pe:  eth3 in VRF A, eth4 in VRF B, both 192.168.1.1/24 and fd00:1::1/64
#   ceA: eth1 192.168.1.2/24 and fd00:1::2/64, the far end of eth3
#   ceB: the same addresses, the far end of eth4
#
# pe runs one bfdd4r with four sessions, one per VRF and family. ceA runs
# a bfdd4r; ceB runs a bfdd4r, or FRR's bfdd in test_frr_as_a_ce.
#
#   sudo ruby -I. test/interop/vrf_test.rb
#
# Without FRR, test_frr_as_a_ce omits, unless BFD4R_REQUIRE_FRR is set:
# then it fails. CI sets it.
class Vrf_Test < Test::Unit::TestCase
  ROOT = File.expand_path('../..', __dir__)
  FRR = '/usr/lib/frr'
  PE4 = '192.168.1.1'
  CE4 = '192.168.1.2'
  PE6 = 'fd00:1::1'
  CE6 = 'fd00:1::2'
  PORTS = { 'A' => 'eth3', 'B' => 'eth4' }.freeze

  def setup
    omit('needs root, for network namespaces and VRFs') unless Process.uid.zero?
    @name = "vrf#{rand(1000)}"
    @dir = Dir.mktmpdir("bfd4r-#{@name}")
    @pids = []
    @pe = "#{@name}-pe"
    sh "ip netns add #{@pe}"
    sh "ip -n #{@pe} link set lo up"
    PORTS.each do |vrf, port|
      ce = ce_ns(vrf)
      sh "ip netns add #{ce}"
      sh "ip -n #{ce} link set lo up"
      sh "ip -n #{@pe} link add #{vrf} type vrf table #{vrf == 'A' ? 100 : 200}"
      sh "ip -n #{@pe} link set #{vrf} up"
      sh "ip -n #{@pe} link add #{port} type veth peer name eth1 netns #{ce}"
      sh "ip -n #{@pe} link set #{port} master #{vrf}"
      sh "ip -n #{@pe} addr add #{PE4}/24 dev #{port}"
      sh "ip -n #{@pe} addr add #{PE6}/64 dev #{port} nodad"
      sh "ip -n #{@pe} link set #{port} up"
      sh "ip -n #{ce} addr add #{CE4}/24 dev eth1"
      sh "ip -n #{ce} addr add #{CE6}/64 dev eth1 nodad"
      sh "ip -n #{ce} link set eth1 up"
    end
  end

  def teardown
    @pids&.each do |pid|
      Process.kill('TERM', pid)
      Process.wait(pid)
    rescue Errno::ESRCH, Errno::ECHILD
      nil
    end
    stop_frr if @frr
    [@pe, ce_ns('A'), ce_ns('B')].each { |ns| system("ip netns del #{ns} 2>/dev/null") } if @name
    FileUtils.rm_rf(@dir) if @dir
  end

  # Four sessions on pe, two per VRF on the same addresses, all Up, each
  # with its VRF; each CE sees only its own two. Then ceA goes away: A's
  # sessions go Down and B's stay Up, so each VRF's receiver gets only
  # its own CE's packets.
  def test_two_vrfs_on_one_address
    start_bfdd4r(@pe, 'pe', PORTS.values.flat_map { |p| [[p, CE4, PE4], [p, CE6, PE6]] })
    start_bfdd4r(ce_ns('A'), 'ceA', [['eth1', PE4, CE4], ['eth1', PE6, CE6]])
    ce_b = start_bfdd4r(ce_ns('B'), 'ceB', [['eth1', PE4, CE4], ['eth1', PE6, CE6]])
    assert(wait_for(15) { pe_states.values.all?('up') && pe_states.size == 4 }, "not up: #{pe_states}\n#{log('pe')}")
    assert_equal({ %w[eth3 192.168.1.2] => 'A', %w[eth3 fd00:1::2] => 'A',
                   %w[eth4 192.168.1.2] => 'B', %w[eth4 fd00:1::2] => 'B' },
                 cli(@pe, 'pe', 'show.sessions').to_h { [[_1['interface'], _1['peer']], _1['vrf']] })
    [ce_ns('A'), ce_ns('B')].zip(%w[ceA ceB]).each do |ns, tag|
      assert_equal %w[up up], cli(ns, tag, 'show.sessions').map { _1['state'] }, tag
      assert_equal %w[default default], cli(ns, tag, 'show.sessions').map { _1['vrf'] }, tag
    end
    assert_equal({}, cli(@pe, 'pe', 'show.counters')['no_session'] || {}, 'every packet found its session')

    @pids.delete(ce_b).then { Process.kill('TERM', _1) && Process.wait(_1) }
    assert(wait_for(5) { pe_states.select { |(i, _), _| i == 'eth4' }.values.none?('up') }, pe_states.inspect)
    assert_equal %w[up up], pe_states.select { |(i, _), _| i == 'eth3' }.values, 'VRF A stays Up'
  end

  # The same with FRR's bfdd as ceB, in the CE's default table.
  def test_frr_as_a_ce
    unless File.executable?("#{FRR}/bfdd")
      why = "needs FRR's bfdd in #{FRR}"
      flunk(why) if ENV['BFD4R_REQUIRE_FRR'] == '1'
      omit(why)
    end
    start_bfdd4r(@pe, 'pe', PORTS.values.flat_map { |p| [[p, CE4, PE4], [p, CE6, PE6]] })
    start_bfdd4r(ce_ns('A'), 'ceA', [['eth1', PE4, CE4], ['eth1', PE6, CE6]])
    start_frr(ce_ns('B'))
    assert(wait_for(20) { pe_states.size == 4 && pe_states.values.all?('up') }, "not up: #{pe_states}\n#{log('pe')}")
    assert_equal %w[up up], frr_states.values_at(PE4, PE6), frr_states.inspect
  end

  private

  def ce_ns(vrf) = "#{@name}-ce#{vrf}"

  def sh(cmd)
    system(cmd) or raise "failed: #{cmd}"
  end

  # A bfdd4r in ns, its sessions [interface, peer, local]. Answers its pid.
  def start_bfdd4r(ns, tag, sessions)
    file = File.join(@dir, "#{tag}.json")
    rows = sessions.map { |i, p, l| { interface: i, peer: p, local: l } }
    File.write(file, JSON.generate({ socket: socket(tag), sessions: rows }))
    pid = Process.spawn('ip', 'netns', 'exec', ns, RbConfig.ruby, "#{ROOT}/exe/bfdd4r", '-f', file,
                        '--log', File.join(@dir, "#{tag}.log"), %i[out err] => File.join(@dir, "#{tag}.out"))
    @pids << pid
    wait_for(10) { cli(ns, tag, 'api.info') rescue nil } or
      raise "bfdd4r #{tag} did not start: #{File.read(File.join(@dir, "#{tag}.out"))}"
    pid
  end

  def socket(tag) = "@bfd4r-#{@name}-#{tag}"

  def cli(ns, tag, method, params = {})
    out, err, status = Open3.capture3('ip', 'netns', 'exec', ns, RbConfig.ruby, "#{ROOT}/exe/bfd4r-cli",
                                      '-s', socket(tag), method, JSON.generate(params))
    raise "bfd4r-cli #{method}: #{err}" unless status.success?

    JSON.parse(out)
  end

  def pe_states
    cli(@pe, 'pe', 'show.sessions').to_h { [[_1['interface'], _1['peer']], _1['state']] }
  end

  def log(tag)
    File.read(File.join(@dir, "#{tag}.log"))
  rescue Errno::ENOENT
    ''
  end

  def frr_run = "/var/run/frr/#{@name}"
  def frr_etc = "/etc/frr/#{@name}"

  def start_frr(ns)
    @frr = true
    FileUtils.mkdir_p([frr_run, frr_etc])
    conf = File.join(frr_etc, 'frr.conf')
    File.write(conf, ["hostname #{@name}", 'bfd', " peer #{PE4} interface eth1", ' exit',
                      " peer #{PE6} interface eth1", ' exit', ''].join("\n"))
    File.write(File.join(frr_etc, 'vtysh.conf'), '')
    sh "chown -R frr:frr #{frr_run} #{frr_etc}"
    %w[zebra bfdd].each do |d|
      out = File.join(@dir, "frr-#{d}.log")
      cmd = "ip netns exec #{ns} #{FRR}/#{d} -N #{@name} -d -f #{conf} -i #{frr_run}/#{d}.pid"
      system("#{cmd} > #{out} 2>&1") or raise "failed: #{cmd}\n#{File.read(out)}"
    end
  end

  def stop_frr
    %w[bfdd zebra].each do |d|
      pid_file = "#{frr_run}/#{d}.pid"
      next unless File.exist?(pid_file)

      begin
        Process.kill('TERM', File.read(pid_file).to_i)
      rescue Errno::ESRCH
        nil
      end
      File.delete(pid_file)
    end
  end

  def frr_states
    out, = Open3.capture3('vtysh', '-N', @name, '-c', 'show bfd peers json')
    JSON.parse(out).to_h { [_1['peer'], _1['status']] }
  rescue JSON::ParserError
    {}
  end

  def wait_for(timeout)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    until yield
      return false if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline

      sleep 0.1
    end
    true
  end
end
