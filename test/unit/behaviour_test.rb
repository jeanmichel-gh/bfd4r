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
require 'bfd/behaviour'

# The scripts as a catalog. What each does to a session is in
# test/functional/behaviours_test.rb.
class Behaviour_Test < Test::Unit::TestCase
  include BFD

  def test_the_eight_scripts_of_the_design
    assert_equal %i[admin_down discr_change fast_while_down flap no_final silent skip_init slow_rx],
                 Behaviour::SCRIPTS.keys.sort
  end

  def test_each_script_says_what_it_does_and_what_is_expected
    Behaviour::SCRIPTS.each_key do |name|
      b = Behaviour.new(name, local_discr: 2)
      assert_not_empty b.description
      assert_not_empty b.expect
      assert_match(/\ARFC 5880 \d/, b.rfc)
    end
  end

  def test_it_answers_as_a_session_does
    b = Behaviour.new(:silent, local_discr: 2, random: Random.new(1))
    out = b.start(0.0)
    assert_equal [Session::Send], out.map(&:class)
    assert_equal [2, :down], [b.local_discr, b.session_state]
    assert_kind_of Float, b.next_due
    assert_equal :init, (b.receive(Control.new(state: :down, my_discr: 1), 0.1) && b.session_state)
  end

  def test_skip_init_never_sends_init
    b = Behaviour.new(:skip_init, local_discr: 2, random: Random.new(1))
    out = b.start(0.0) + b.receive(Control.new(state: :down, my_discr: 1), 0.1)
    assert_equal %i[up up], out.grep(Session::Send).map { _1.packet.state_name }
    assert_equal :init, b.session_state, 'its own session is correct'
  end

  def test_an_unknown_script_is_refused
    assert_raise(ArgumentError) { Behaviour.new(:sulk, local_discr: 2) }
  end
end
