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
require 'time'
require_relative 'lab'
require_relative 'fault_matrix'
$LOAD_PATH.unshift(Lab::ROOT) unless $LOAD_PATH.include?(Lab::ROOT)
require 'bfd4r'

# The fault matrix (routescope docs/design/bfd.md, step 5b): every entry
# of BFD::Fault::CATALOG sent by bfd4r-sim to three receivers, bfdd4r,
# FRR's bfdd and BIRD, and two controls. bfdd4r must do what RFC 5880
# expects; FRR's and BIRD's answers are recorded, not asserted. With
# BFD4R_MATRIX_DOC set to a path, it writes the matrix there
# (docs/fault-matrix.md).
#
#   sudo ruby -I. test/interop/fault_matrix_test.rb
#
# Root. Without FRR or BIRD it omits, unless BFD4R_REQUIRE_FRR or
# BFD4R_REQUIRE_BIRD is set.
class FaultMatrix_Test < Test::Unit::TestCase
  self.test_order = :defined

  COUNT = 16
  EVERY = 0.15

  @rows = nil
  class << self
    attr_accessor :rows
  end

  # The two controls first: a valid packet keeps the session Up, and no
  # packet takes it Down. They show the method reads both ways.
  def self.cases
    up = { 'state' => 'up', 'detect_mult' => 3, 'desired_min_tx' => 300_000, 'required_min_rx' => 300_000 }
    [{ name: :valid, description: 'a valid Up packet, the control', expect: :accept, rfc: '5880 6.8.6',
       body: ->(d) { ['/api/send', up.merge(d)] } },
     { name: :nothing, description: 'no packet, the other control', expect: :discard, rfc: '5880 6.8.4',
       body: nil }] +
      BFD::Fault.catalog.map do |e|
        e.merge(rfc: e[:rfc].sub('RFC ', ''),
                body: e[:auth] == :none ? ->(d) { ['/api/fault', d.merge('case' => e[:name].to_s)] } : nil,
                skip: e[:auth] != :none)
      end
  end

  def self.measured
    self.rows ||= cases.map { |c| c.slice(:name, :description, :expect, :rfc) }
  end

  def self.shutdown
    path = ENV['BFD4R_MATRIX_DOC']
    return unless path && rows && FaultMatrix::RECEIVERS.keys.all? { |k| rows.all? { _1.key?(k) } }

    File.write(path, FaultMatrix.render(rows, versions: versions, date: Time.now.utc.strftime('%F'),
                                              kernel: `uname -r`.strip))
  end

  def self.versions
    frr = `#{Lab::FRR}/bfdd --version 2>&1`[/version (\S+)/, 1]
    bird = `bird --version 2>&1`[/version (\S+)/, 1]
    "bfd4r #{BFD::VERSION}, Ruby #{RUBY_VERSION}, FRR #{frr}, BIRD #{bird}"
  end

  def run_receiver(peer)
    why = Lab.missing(peer == :bfdd4r ? :none : peer)
    if why
      flunk(why) if ENV["BFD4R_REQUIRE_#{peer.upcase}"] == '1'
      omit(why)
    end
    @lab = Lab.new("fm#{peer}#{rand(1000)}").start(peer: peer, ours: :sim, families: %i[v4])
    self.class.cases.zip(self.class.measured).each do |c, row|
      row[peer] = c[:skip] ? 'not run: needs authentication' : measure(c, peer)
    end
  ensure
    @lab&.stop
  end

  def theirs
    @lab.theirs[Lab::OURS4]
  end

  # bfdd4r's discards, by finding: its session's and those of no session.
  def discards
    s = @lab.peer_cli('show.sessions').find { _1['peer'] == Lab::OURS4 }
    s['discards'].merge(@lab.peer_cli('show.counters')['no_session'])
  end

  def measure(c, peer)
    @lab.sim('/api/stop', {}) if @lab.sim('/api/status')['peer']
    @lab.sim('/api/peer', 'to' => Lab::PEER4)
    assert(@lab.wait_for(15) { @lab.sim('/api/status').dig('peer', 'state') == 'up' && theirs == 'up' },
           "#{c[:name]}: not Up with #{peer}: #{@lab.theirs}")
    status = @lab.sim('/api/status')['peer']
    d = { 'to' => Lab::PEER4, 'my_discr' => status['local_discr'], 'your_discr' => status['remote_discr'] }
    before = peer == :bfdd4r ? discards : nil
    @lab.sim('/api/behave', 'name' => 'silent', 'after' => 0)
    if c[:body]
      @lab.sim_repeat(*c[:body].call(d), count: COUNT, every: EVERY)
    else
      sleep COUNT * EVERY
    end
    state = theirs
    return FaultMatrix.outcome(state) unless peer == :bfdd4r

    out = FaultMatrix.ours(state, before, discards)
    # bfdd4r is held to the RFC: what it must discard, it discards, and
    # counts under the catalog's finding.
    assert_equal true, FaultMatrix.agrees?(c[:expect], out), "bfdd4r, #{c[:name]}: #{out}" unless c[:expect] == :record
    assert_match(/discarded: .*\b#{c[:finding]}\b/, out, "bfdd4r, #{c[:name]}") if c[:finding] && c[:expect] == :discard
    out
  end

  def test_bfdd4r
    run_receiver(:bfdd4r)
  end

  def test_frr
    run_receiver(:frr)
  end

  def test_bird
    run_receiver(:bird)
  end
end
