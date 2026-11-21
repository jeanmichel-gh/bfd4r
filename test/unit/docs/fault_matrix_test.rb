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

# docs/fault-matrix.md is written by test/interop/fault_matrix_test.rb,
# which needs root, FRR and BIRD. This needs none: it fails when the
# catalog gains or loses an entry the document does not show, so a new
# fault cannot go in without the matrix being run again. As vtep4r's.
class FaultMatrixDoc_Test < Test::Unit::TestCase
  DOC = File.expand_path('../../../docs/fault-matrix.md', __dir__)

  def rows
    File.read(DOC).lines.grep(/\A\| `/).to_h { |l| [l[/\A\| `([^`]+)`/, 1], l.split('|').map(&:strip)] }
  end

  def test_every_catalog_entry_and_the_two_controls_have_a_row
    assert_equal %w[valid nothing] + BFD::Fault.names.map(&:to_s), rows.keys
  end

  def test_each_row_says_what_the_rfc_expects_as_the_catalog_does
    BFD::Fault.catalog.each do |e|
      assert_match(/\A#{e[:expect]} \(#{Regexp.escape(e[:rfc].sub('RFC ', ''))}\)\z/, rows[e[:name].to_s][3], e[:name].to_s)
    end
  end

  def test_three_receivers
    assert_equal ['bfdd4r', 'FRR bfdd', 'BIRD'], File.read(DOC)[/^\| Case .*$/].split('|').map(&:strip)[4..]
  end

  def test_it_says_it_is_generated
    assert_match(/\*\*Generated\*\* by `test\/interop\/fault_matrix_test.rb` on \d{4}-\d\d-\d\d, Linux \S+,/, File.read(DOC))
  end
end
