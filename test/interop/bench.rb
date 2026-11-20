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

# The timing bench (routescope docs/design/bfd.md, "Timers"): bfdd4r
# against FRR's bfdd at a given interval, with every core kept busy, for
# a given time. It counts flaps on both sides and measures the gaps
# between the packets bfdd4r sent, from a capture in FRR's namespace.
# Root. Prints one JSON object; docs/timing.md keeps the results.
#
#   sudo ruby test/interop/bench.rb --interval 50 --minutes 60
#   sudo ruby test/interop/bench.rb --interval 300 --minutes 5 --busy 0

require 'json'
require 'optparse'
require 'etc'
require_relative 'lab'
require_relative '../support/pcap'

opts = { interval: 50, mult: 3, minutes: 1.0, busy: Etc.nprocessors, peer: :frr }
OptionParser.new do |o|
  o.on('--interval MS', Integer) { opts[:interval] = _1 }
  o.on('--mult N', Integer) { opts[:mult] = _1 }
  o.on('--minutes M', Float) { opts[:minutes] = _1 }
  o.on('--busy N', Integer, 'processes spinning; default: one per core') { opts[:busy] = _1 }
end.parse!

why = Lab.missing(opts[:peer])
abort "bench: #{why}" if why

def now = Process.clock_gettime(Process::CLOCK_MONOTONIC)

lab = Lab.new('bfdbench')
pcap = File.join(lab.dir, 'ours.pcap')
spinners = []
tcpdump = nil
begin
  us = opts[:interval] * 1000
  lab.start(peer: opts[:peer], families: %i[v4], tx: us, rx: us, mult: opts[:mult])
  lab.wait_for(15) { lab.ours.all? { _1['state'] == 'up' } } or abort 'bench: the session did not come up'
  tcpdump = Process.spawn('ip', 'netns', 'exec', "#{lab.name}-peer", 'tcpdump', '-i', Lab::IF, '-U', '-w', pcap,
                          "udp port 3784 and src #{Lab::OURS4}", %i[out err] => File::NULL)
  spinners = Array.new(opts[:busy]) { Process.spawn(RbConfig.ruby, '-e', 'x = 0; loop { x += 1 }') }
  start = now
  samples = []
  while now - start < opts[:minutes] * 60
    sleep 5
    row = lab.our(Lab::PEER4)
    samples << [now - start, row['state'], row['flaps']]
  end
  spinners.each { Process.kill('KILL', _1) }
  spinners.each { Process.wait(_1) }
  spinners = []
  sleep 0.5
  Process.kill('INT', tcpdump)
  Process.wait(tcpdump)
  tcpdump = nil
  row = lab.our(Lab::PEER4)
  frr = JSON.parse(lab.frr('show bfd peers counters json')).find { _1['peer'] == Lab::OURS4 } || {}
  times = Pcap.bfd_times(pcap)
  gaps = times.each_cons(2).map { (_2 - _1) * 1000 }.sort
  pct = ->(q) { gaps.empty? ? nil : gaps[[(gaps.size * q).ceil - 1, 0].max].round(2) }
  detection = opts[:interval] * opts[:mult]
  puts JSON.pretty_generate(
    interval_ms: opts[:interval], mult: opts[:mult], minutes: opts[:minutes], busy: opts[:busy],
    cores: Etc.nprocessors, ruby: RUBY_VERSION, peer: opts[:peer],
    ours: { flaps: row['flaps'], state: row['state'], discards: row['discards'], packets_out: row['packets_out'] },
    frr: frr.slice('session-up', 'session-down', 'control-packet-input', 'control-packet-output'),
    gaps_ms: { packets: times.size, min: gaps.first&.round(2), p50: pct.call(0.5), p99: pct.call(0.99),
               p999: pct.call(0.999), max: gaps.last&.round(2), over_interval: gaps.count { _1 > opts[:interval] },
               over_detection: gaps.count { _1 >= detection } },
    samples_down: samples.count { _1[1] != 'up' }
  )
ensure
  spinners.each do |pid|
    Process.kill('KILL', pid)
    Process.wait(pid)
  rescue Errno::ESRCH, Errno::ECHILD
    nil
  end
  if tcpdump
    Process.kill('INT', tcpdump)
    Process.wait(tcpdump)
  end
  lab.stop
end
