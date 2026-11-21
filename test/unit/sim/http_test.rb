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
require 'bfd/sim/http'

# bfd4r-sim's HTTP rules through #handle, with no socket.
class SimHttp_Test < Test::Unit::TestCase
  include BFD

  class Wire
    def deliver(*, **); end
    def listen(_); end
  end

  POST = { 'x-bfd4r' => 'routescope' }.freeze

  def setup
    clock = Runtime::ManualClock.new
    inj = Sim::Injector.new(transport: Wire.new, scheduler: Runtime::Scheduler.new(clock), local: '10.0.0.2')
    @calls = 0
    @http = Sim::Http.new(inj, on_loop: lambda { |&b|
      @calls += 1
      b.call
    })
  end

  def test_index
    s, a = @http.handle('GET', '/')
    assert_equal 200, s
    assert_equal 'X-BFD4R: routescope', a[:post_header]
    assert_equal %w[/api/behave /api/fault /api/peer /api/send /api/stop], a[:actions].keys
    assert_equal %w[/api/catalog /api/events /api/received /api/sent /api/status], a[:reads]
  end

  def test_reads_run_on_the_loop
    %w[/api/status /api/sent /api/received /api/catalog /api/events?since=0].each do |path|
      assert_equal 200, @http.handle('GET', path)[0], path
    end
    assert_equal 5, @calls
  end

  # routescope docs/design/bfd.md: without the header, 403.
  def test_a_post_needs_the_header
    s, a = @http.handle('POST', '/api/peer', {}, '{"to":"10.0.0.1"}')
    assert_equal 403, s
    assert_match(/X-BFD4R: routescope/, a[:error])
    assert_equal 403, @http.handle('POST', '/api/peer', { 'x-bfd4r' => 'other' }, '{"to":"10.0.0.1"}')[0]
    assert_equal 0, @calls
  end

  def test_actions
    s, a = @http.handle('POST', '/api/peer', POST, '{"to":"10.0.0.1"}')
    assert_equal [200, '10.0.0.1'], [s, a[:to]]
    assert_equal 409, @http.handle('POST', '/api/peer', POST, '{"to":"10.0.0.1"}')[0]
    assert_equal 200, @http.handle('POST', '/api/behave', POST, '{"name":"silent"}')[0]
    assert_equal 200, @http.handle('POST', '/api/fault', POST, '{"case":"multipoint"}')[0]
    assert_equal 200, @http.handle('POST', '/api/stop', POST, '')[0]
  end

  def test_wrong_method_path_and_body
    assert_equal 405, @http.handle('POST', '/api/status', POST)[0]
    assert_equal 405, @http.handle('GET', '/api/send')[0]
    assert_equal 404, @http.handle('GET', '/api/nope')[0]
    assert_equal 400, @http.handle('POST', '/api/send', POST, 'not json')[0]
    assert_equal 400, @http.handle('POST', '/api/send', POST, '[1]')[0]
    assert_equal 400, @http.handle('POST', '/api/send', POST, '{"to":"10.0.0.1","ttl":"x"}')[0]
  end
end
