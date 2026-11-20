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
require 'stringio'
require 'bfd/daemon/cli'

class CLI_Test < Test::Unit::TestCase
  include BFD::Daemon

  # Records the call and answers what it is told.
  class FakeClient
    attr_reader :calls

    def initialize(result = nil, error = nil)
      @result = result
      @error = error
      @calls = []
    end

    def call(method, params)
      @calls << [method, params]
      raise BFD::Daemon::Client::Error, @error if @error

      @result
    end

    def close; end
  end

  def run_cli(argv, client = FakeClient.new({ 'ok' => true }))
    out = StringIO.new
    err = StringIO.new
    status = CLI.new(out, err, client).start(argv)
    [status, out.string, err.string, client]
  end

  def test_params
    assert_equal({}, CLI.params([]))
    assert_equal({ 'interface' => 'eth1', 'detect_mult' => 5, 'down' => true },
                 CLI.params(%w[interface=eth1 detect_mult=5 down=true]))
    assert_equal({ 'a' => [1] }, CLI.params(['{"a":', '[1]}']))
    assert_raise(ArgumentError) { CLI.params(%w[novalue]) }
  end

  def test_a_call_and_its_json
    status, out, _, client = run_cli(%w[session.admin interface=eth1 peer=10.0.0.2 down=false])
    assert_equal [0, "{\"ok\":true}\n"], [status, out]
    assert_equal [['session.admin', { 'interface' => 'eth1', 'peer' => '10.0.0.2', 'down' => false }]], client.calls
  end

  def test_an_error_is_bfdd4rs_message
    status, _, err = run_cli(%w[show.foo], FakeClient.new(nil, 'unknown method "show.foo"'))
    assert_equal [1, "bfd4r-cli: unknown method \"show.foo\"\n"], [status, err]
  end

  def test_help_and_version
    status, out = run_cli(%w[-h])
    assert_equal 0, status
    assert_match(/Usage: bfd4r-cli/, out)
    assert_equal [0, "#{BFD::VERSION}\n"], run_cli(%w[--version])[0, 2]
    assert_equal 1, run_cli([])[0]
  end
end
