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
require 'bfd/sim/config'

class SimConfig_Test < Test::Unit::TestCase
  include BFD

  def test_the_keys
    c = Sim::Config.new('local' => '10.0.0.2', 'interface' => 'eth1')
    assert_equal ['10.0.0.2', 'eth1', '127.0.0.1:8080'], [c.local, c.interface, c.api]
    assert_equal 'fd00::2', Sim::Config.new('local' => 'fd00::2', 'api' => '9000').local
  end

  def test_refusals
    { {} => /local: the address/,
      { 'local' => 'x' } => /not an address/,
      { 'local' => '10.0.0.2', 'port' => 1 } => /unknown key port/,
      { 'local' => '10.0.0.2', 'sessions' => [] } => /bfdd4r's file/ }.each do |h, message|
      assert_match(message, assert_raise(Sim::Config::Error) { Sim::Config.new(h) }.message)
    end
    assert_raise(Sim::Config::Error) { Sim::Config.new([]) }
  end
end
