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
require 'bfd/daemon/runner'
require 'bfd/daemon/api'

# The API's methods, on a Runner that is not started, so each call runs
# inline on a manual clock. The socket and the stream are in
# test/functional/programs_test.rb.
class Api_Test < Test::Unit::TestCase
  include BFD

  class Wire
    def deliver(*, **); end
  end

  def setup
    @runner = Daemon::Runner.new(transport: Wire.new, clock: Runtime::ManualClock.new, random: Random.new(1))
    @api = Daemon::Api.new(@runner, path: "\0bfdd4r-unit")
  end

  def call(method, params = {})
    JSON.parse(JSON.generate(@api.handle('id' => 1, 'method' => method, 'params' => params)))
  end

  KEY = { 'interface' => 'eth1', 'peer' => '10.0.0.2' }.freeze

  def add(client = 'isisd', **more)
    call('session.add', KEY.merge('local' => '10.0.0.1', 'client' => client).merge(more.transform_keys(&:to_s)))
  end

  def test_api_info_for_routescopes_contract
    r = call('api.info')['result']
    assert_equal %w[api.info events.subscribe events.unsubscribe session.add session.admin session.delete
                    session.set show.counters show.sessions], r['methods']
    assert_equal %w[session config overflow], r['event_kinds']
    assert_equal [BFD::VERSION, 1], r.values_at('version', 'api')
  end

  def test_session_add_answers_the_row
    r = add['result']
    assert_equal ['eth1', '10.0.0.2', '10.0.0.1', ['isisd'], 'down'], r.values_at('interface', 'peer', 'local', 'clients', 'state')
    assert_equal 0, r['variables']['bfd.RemoteDiscr']
    assert_equal ['isisd', 'bgp4rd'], add('bgp4rd')['result']['clients']
  end

  def test_session_add_refuses_unknown_keys_and_needs_a_client
    assert_match(/unknown session key hold/, add(hold: 3)['error'])
    assert_match(/client/, call('session.add', KEY.merge('local' => '10.0.0.1'))['error'])
    assert_match(/floor/, add(desired_min_tx: 1000)['error'])
  end

  def test_session_delete
    add('isisd')
    add('bgp4rd')
    assert_equal ['bgp4rd'], call('session.delete', KEY.merge('client' => 'isisd'))['result']['clients']
    r = call('session.delete', KEY.merge('client' => 'bgp4rd'))['result']
    assert_equal [[], 'admin_down'], r.values_at('clients', 'state')
  end

  def test_session_admin_and_set
    add
    assert_equal 'admin_down', call('session.admin', KEY.merge('down' => true))['result']['state']
    assert_equal 'down', call('session.admin', KEY.merge('down' => false))['result']['state']
    assert_match(/true or false/, call('session.admin', KEY.merge('down' => 'yes'))['error'])
    assert_equal 5, call('session.set', KEY.merge('detect_mult' => 5))['result']['variables']['bfd.DetectMult']
    assert_match(/unknown timer hold/, call('session.set', KEY.merge('hold' => 1))['error'])
  end

  def test_an_unknown_session
    assert_match(/no session to 10.0.0.2 on eth1/, call('session.admin', KEY.merge('down' => true))['error'])
  end

  def test_show_sessions_all_or_one
    add
    call('session.add', 'interface' => 'eth2', 'peer' => '10.0.1.2', 'local' => '10.0.1.1', 'client' => 'x')
    assert_equal 2, call('show.sessions')['result'].size
    assert_equal ['eth1'], call('show.sessions', KEY)['result'].map { _1['interface'] }
  end

  def test_show_counters
    add
    @runner.core.receive("\0" * 24, interface: 'eth9', source: '10.9.9.9', ttl: 255)
    assert_equal({ 'sessions' => 1, 'no_session' => { 'unknown_peer' => 1 } }, call('show.counters')['result'])
  end

  def test_a_bad_request_is_answered
    assert_match(/unknown method "show.foo"/, call('show.foo')['error'])
    assert_match(/is a stream/, call('events.subscribe')['error'])
  end
end
