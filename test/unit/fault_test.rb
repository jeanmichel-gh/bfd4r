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
require 'bfd/fault'

# The catalog against Validation: every entry makes the one finding it
# names, and under :rfc is discarded or accepted as its expect says.
class Fault_Test < Test::Unit::TestCase
  include BFD

  MY = 9
  YOUR = 7

  def findings(name)
    Validation.check(Fault.wire(name, my_discr: MY, your_discr: YOUR), **Fault.context(name, your_discr: YOUR))
  end

  def test_each_entry_makes_its_one_finding
    Fault.catalog.each do |e|
      assert_equal [e[:finding]], findings(e[:name]).map(&:name), e[:name].to_s
    end
  end

  def test_the_rfc_policy_does_what_each_entry_expects
    Fault.catalog.each do |e|
      verdict = Validation.decide(Fault.wire(e[:name], my_discr: MY, your_discr: YOUR),
                                  **Fault.context(e[:name], your_discr: YOUR))
      assert_equal({ discard: :discard, record: :accept }.fetch(e[:expect]), verdict, e[:name].to_s)
    end
  end

  def test_every_finding_has_an_entry
    assert_equal Validation::RULES.keys.sort, Fault.catalog.map { _1[:finding] }.sort
  end

  def test_the_record_entries_are_the_ones_the_rfc_leaves_open
    assert_equal %i[desired_min_tx_zero poll_and_final], Fault.catalog.select { _1[:expect] == :record }.map { _1[:name] }.sort
    Fault.catalog.each do |e|
      assert_equal Validation::RULES[e[:finding]][0] == :report, e[:expect] == :record, e[:name].to_s
    end
  end

  def test_names_are_unique_and_entries_complete
    assert_equal Fault.names.uniq, Fault.names
    Fault.catalog.each do |e|
      assert_not_empty e[:description]
      assert_match(/\ARFC 588[01] \d/, e[:rfc])
      assert_include [255, 254], e[:ttl]
      assert_include %i[none sha1], e[:auth]
    end
  end

  def test_an_entry_is_built_for_the_session
    c = Fault.build(:detect_mult_zero, my_discr: 0x11, your_discr: 0x22)
    assert_equal [0x11, 0x22, :up, 0], [c.my_discr, c.your_discr, c.state_name, c.detect_mult]
  end

  def test_truncated_is_octets
    assert_equal 20, Fault.wire(:truncated, my_discr: MY, your_discr: YOUR).bytesize
  end

  def test_ttl_254_is_a_correct_packet_sent_low
    e = Fault.entry(:ttl_254)
    assert_equal 254, e[:ttl]
    assert_equal [], Fault.build(:ttl_254, my_discr: MY, your_discr: YOUR).errors
  end

  def test_an_unknown_name_is_refused
    assert_raise(ArgumentError) { Fault.build(:nope, my_discr: 1, your_discr: 2) }
  end
end
