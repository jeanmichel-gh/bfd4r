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

require 'json'
require 'fileutils'
require 'tmpdir'
require 'open3'

# Two network namespaces joined by a veth pair, with IPv4 and IPv6 on
# it: bfdd4r in one ("ours"), and FRR's bfdd or BIRD in the other ("peer"),
# run natively as ospfv2's and isis's interop tiers run FRR. Needs root,
# iproute2, FRR and BIRD 2.
#
#   lab = Lab.new('t1').start(peer: :frr)
#   lab.wait_for { lab.ours.all? { _1['state'] == 'up' } }
#   lab.stop
#
# BFD4R_REQUIRE_FRR, BFD4R_REQUIRE_BIRD: fail rather than omit when the
# tier cannot run (routescope docs/design/protocol-conventions.md, part 10).
class Lab
  ROOT = File.expand_path('../..', __dir__)
  FRR = '/usr/lib/frr'
  OURS4 = '10.0.12.1'
  PEER4 = '10.0.12.2'
  OURS6 = 'fd00:12::1'
  PEER6 = 'fd00:12::2'
  IF = 'veth0'

  # Why the tier cannot run with this peer, or nil.
  def self.missing(peer)
    return 'needs root, for network namespaces' unless Process.uid.zero?
    return 'needs iproute2' unless system('which ip > /dev/null')

    case peer
    when :frr
      return 'needs FRR (zebra, bfdd, vtysh)' unless %w[zebra bfdd].all? { File.executable?("#{FRR}/#{_1}") }
      return 'needs vtysh' unless system('which vtysh > /dev/null')

      enforced = apparmor_enforced('bfdd')
      "AppArmor enforces a profile for bfdd, which denies its pid file under a pathspace: " \
        'sudo apparmor_parser -R /etc/apparmor.d/bfdd' if enforced
    when :bird
      'needs BIRD 2 (bird, birdc)' unless system('which bird birdc > /dev/null')
    end
  end

  def self.apparmor_enforced(daemon)
    File.read('/sys/kernel/security/apparmor/profiles').match?(/^(#{daemon}|#{FRR}\/#{daemon}) \(enforce\)$/)
  rescue Errno::ENOENT, Errno::EACCES
    false
  end

  attr_reader :name, :dir, :peer

  def initialize(name)
    @name = name
    @ours_ns = "#{name}-ours"
    @peer_ns = "#{name}-peer"
    @dir = Dir.mktmpdir("bfd4r-#{name}")
    @run = "/var/run/frr/#{name}"
    @etc = "/etc/frr/#{name}"
  end

  # peer: :frr or :bird. families: which sessions, :v4 and :v6.
  # timers: bfdd4r's, in microseconds; the peer is set to match.
  # floor: bfdd4r's, when a bench goes under the default.
  def start(peer:, families: %i[v4 v6], tx: 300_000, rx: 300_000, mult: 3, floor: nil)
    @floor = floor
    @peer = peer
    @families = families
    cleanup
    sh "ip netns add #{@ours_ns}"
    sh "ip netns add #{@peer_ns}"
    sh "ip link add #{IF} netns #{@ours_ns} type veth peer name #{IF} netns #{@peer_ns}"
    { @ours_ns => [OURS4, OURS6], @peer_ns => [PEER4, PEER6] }.each do |ns, (v4, v6)|
      sh "ip -n #{ns} link set lo up"
      # Linux drops a configured IPv6 address when its link goes down,
      # unless told to keep it; a link test brings it back up.
      sh "ip netns exec #{ns} sysctl -qw net.ipv6.conf.#{IF}.keep_addr_on_down=1"
      sh "ip -n #{ns} addr add #{v4}/24 dev #{IF}"
      sh "ip -n #{ns} addr add #{v6}/64 dev #{IF} nodad"
      sh "ip -n #{ns} link set #{IF} up"
    end
    peer == :frr ? start_frr(tx, rx, mult) : start_bird(tx, rx, mult)
    start_ours(tx, rx, mult)
    self
  end

  def stop
    stop_ours
  ensure
    cleanup
  end

  def peers
    @families.map { _1 == :v4 ? PEER4 : PEER6 }
  end

  # ---- bfdd4r ----

  def socket = "@bfd4r-#{@name}"

  # bfd4r-cli in our namespace, where the abstract socket is.
  def cli(method, params = {})
    out, err, status = Open3.capture3('ip', 'netns', 'exec', @ours_ns, RbConfig.ruby, "#{ROOT}/exe/bfd4r-cli",
                                      '-s', socket, method, JSON.generate(params))
    raise "bfd4r-cli #{method}: #{err}" unless status.success?

    JSON.parse(out)
  end

  # Our sessions, one row each.
  def ours
    cli('show.sessions')
  end

  def our(peer_address)
    ours.find { _1['peer'] == peer_address }
  end

  def log
    File.read(File.join(@dir, 'bfdd4r.log'))
  rescue Errno::ENOENT
    ''
  end

  # ---- the peer ----

  # The peer's view of each session: { address => 'up' | 'down' | ... }.
  def theirs
    @peer == :frr ? frr_sessions : bird_sessions
  end

  def frr(cmd)
    out, = Open3.capture3('vtysh', '-N', @name, '-c', cmd)
    out
  end

  def birdc(cmd)
    out, = Open3.capture3('birdc', '-s', bird_socket, cmd)
    out
  end

  # The link goes down on the peer's side, or comes back.
  def link(up)
    sh "ip -n #{@peer_ns} link set #{IF} #{up ? 'up' : 'down'}"
  end

  # Loss on the peer's side of the link, as a percentage, with netem.
  def loss(percent)
    action = percent.zero? ? 'del' : 'replace'
    cmd = "tc -n #{@peer_ns} qdisc #{action} dev #{IF} root"
    cmd += " netem loss #{percent}%" unless percent.zero?
    system("#{cmd} 2>/dev/null")
  end

  # The peer's session to us, administratively down or back.
  def peer_admin(down)
    if @peer == :frr
      @families.each do |f|
        frr_conf("peer #{f == :v4 ? OURS4 : OURS6} interface #{IF}", down ? 'shutdown' : 'no shutdown')
      end
    else
      birdc(down ? 'disable bfd1' : 'enable bfd1')
    end
  end

  def wait_for(timeout = 20)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    until yield
      return false if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline

      sleep 0.1
    end
    true
  end

  private

  def start_ours(tx, rx, mult)
    sessions = @families.map do |f|
      { interface: IF, peer: f == :v4 ? PEER4 : PEER6, local: f == :v4 ? OURS4 : OURS6,
        desired_min_tx: tx, required_min_rx: rx, detect_mult: mult }
    end
    file = File.join(@dir, 'bfdd4r.json')
    File.write(file, JSON.generate({ socket: socket, floor: @floor, sessions: sessions }.compact))
    @ours_pid = Process.spawn('ip', 'netns', 'exec', @ours_ns, RbConfig.ruby, "#{ROOT}/exe/bfdd4r", '-f', file,
                              '--log', File.join(@dir, 'bfdd4r.log'), %i[out err] => File.join(@dir, 'bfdd4r.out'))
    wait_for(10) { cli('api.info') rescue nil } or raise "bfdd4r did not start: #{File.read(File.join(@dir, 'bfdd4r.out'))}"
  end

  def stop_ours
    return unless @ours_pid

    Process.kill('TERM', @ours_pid)
    Process.wait(@ours_pid)
  rescue Errno::ESRCH, Errno::ECHILD
    nil
  ensure
    @ours_pid = nil
  end

  def start_frr(tx, rx, mult)
    FileUtils.mkdir_p([@run, @etc])
    lines = ["hostname #{@name}", 'bfd']
    @families.each do |f|
      lines << " peer #{f == :v4 ? OURS4 : OURS6} interface #{IF}"
      lines << "  transmit-interval #{tx / 1000}"
      lines << "  receive-interval #{rx / 1000}"
      lines << "  detect-multiplier #{mult}"
      lines << ' exit'
    end
    conf = File.join(@etc, 'frr.conf')
    File.write(conf, "#{lines.join("\n")}\n")
    File.write(File.join(@etc, 'vtysh.conf'), '')
    sh "chown -R frr:frr #{@run} #{@etc}"
    %w[zebra bfdd].each do |d|
      log = File.join(@dir, "frr-#{d}.log")
      cmd = "ip netns exec #{@peer_ns} #{FRR}/#{d} -N #{@name} -d -f #{conf} -i #{@run}/#{d}.pid"
      system("#{cmd} > #{log} 2>&1") or raise "failed: #{cmd}\n#{File.read(log)}"
    end
  end

  def frr_conf(*lines)
    Open3.capture3('vtysh', '-N', @name, '-c', 'configure terminal', '-c', 'bfd', *lines.flat_map { ['-c', _1] })
  end

  def frr_sessions
    JSON.parse(frr('show bfd peers json')).to_h { [_1['peer'], _1['status']] }
  rescue JSON::ParserError
    {}
  end

  def bird_socket = File.join(@dir, 'bird.ctl')

  def start_bird(tx, rx, mult)
    neighbors = @families.map { |f| "  neighbor #{f == :v4 ? OURS4 : OURS6} dev \"#{IF}\";" }
    conf = File.join(@dir, 'bird.conf')
    File.write(conf, <<~CONF)
      router id #{PEER4};
      protocol device {}
      protocol bfd bfd1 {
        interface "#{IF}" { min rx interval #{rx / 1000} ms; min tx interval #{tx / 1000} ms; multiplier #{mult}; };
      #{neighbors.join("\n")}
      }
    CONF
    @bird_pid = Process.spawn('ip', 'netns', 'exec', @peer_ns, 'bird', '-f', '-c', conf, '-s', bird_socket,
                              %i[out err] => File.join(@dir, 'bird.log'))
    wait_for(10) { File.socket?(bird_socket) } or raise "bird did not start: #{File.read(File.join(@dir, 'bird.log'))}"
  end

  # birdc's "show bfd sessions": address, interface, state, ...
  def bird_sessions
    birdc('show bfd sessions').lines.filter_map do |l|
      f = l.split
      [f[0], f[2].downcase] if f.size >= 3 && f[0].match?(/\A[\h.:]+\z/) && f[0].include?(f[0].include?(':') ? ':' : '.')
    end.to_h
  end

  def cleanup
    if @bird_pid
      begin
        Process.kill('TERM', @bird_pid)
        Process.wait(@bird_pid)
      rescue Errno::ESRCH, Errno::ECHILD
        nil
      end
      @bird_pid = nil
    end
    %w[bfdd zebra].each do |d|
      pid_file = "#{@run}/#{d}.pid"
      next unless File.exist?(pid_file)

      begin
        Process.kill('TERM', File.read(pid_file).to_i)
      rescue Errno::ESRCH
        nil
      end
      File.delete(pid_file)
    end
    [@peer_ns, @ours_ns].each { |ns| system("ip netns del #{ns} 2>/dev/null") }
  end

  def sh(cmd)
    system(cmd) or raise "failed: #{cmd}"
  end
end
