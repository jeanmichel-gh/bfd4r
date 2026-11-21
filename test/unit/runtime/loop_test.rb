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
require 'bfd/runtime/loop'

# Runtime::Loop: calls and packets run on its one thread, in order.
class Loop_Test < Test::Unit::TestCase
  include BFD::Runtime

  def test_calls_and_packets_run_on_the_loop
    seen = Thread::Queue.new
    loop = Loop.new { |octets, **meta| seen.push([Thread.current, octets, meta]) }
    assert_equal 2, loop.on_loop { 2 }, 'inline before start'
    loop.start
    thread = loop.on_loop { Thread.current }
    assert_not_equal Thread.current, thread
    loop.push_packet('x', source: 'a')
    assert_equal [thread, 'x', { source: 'a' }], seen.pop(timeout: 5)
    assert_raise(ZeroDivisionError) { loop.on_loop { 1 / 0 } }
    assert loop.running?, 'an error in a call does not stop the loop'
  ensure
    loop&.stop
  end

  def test_timers_fire
    loop = Loop.new.start
    fired = Thread::Queue.new
    loop.on_loop { loop.scheduler.after(0.01) { fired.push(Thread.current) } }
    assert_not_nil fired.pop(timeout: 5)
  ensure
    loop&.stop
  end
end
