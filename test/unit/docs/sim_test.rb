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
require 'bfd/sim/http'

# docs/sim.md lists the HTTP paths, the behaviours and the event kinds;
# the code is the measure.
class SimDoc_Test < Test::Unit::TestCase
  DOC = File.read(File.expand_path('../../../docs/sim.md', __dir__))

  def test_every_path_is_in_the_table_and_no_other
    listed = DOC.scan(%r{^\| `(?:GET|POST) (/api/\w+)` \|}).flatten.sort
    assert_equal (BFD::Sim::Http::READS.keys + BFD::Sim::Http::ACTIONS.keys).sort, listed
  end

  def test_every_behaviour
    listed = DOC.scan(/^\| `(\w+)` \| [^|]+ \|$/).flatten.map(&:to_sym)
    assert_equal BFD::Behaviour::SCRIPTS.keys, listed
  end

  def test_the_event_kinds
    BFD::Sim::Injector::EVENT_KINDS.each { |k| assert_match(/`#{k}`/, DOC, k.to_s) }
  end
end
