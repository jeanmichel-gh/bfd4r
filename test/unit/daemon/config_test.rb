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
require 'tempfile'
require 'bfd/daemon/config'

class Config_Test < Test::Unit::TestCase
  include BFD::Daemon

  def test_an_empty_file_is_the_defaults
    c = Config.new
    assert_equal ['@bfdd4r', 300_000, []], [c.socket, c.floor, c.sessions]
  end

  def test_the_floor
    assert_equal 50_000, Config.new('floor' => '50000').floor
    [0, -1, 'fast', nil].each do |v|
      e = assert_raise(Config::Error) { Config.new('floor' => v) }
      assert_match(/floor/, e.message)
    end
  end

  def test_sessions
    c = Config.new('sessions' => [{ 'interface' => 'eth1', 'peer' => '10.0.0.2', 'local' => '10.0.0.1',
                                    'desired_min_tx' => 100_000, 'detect_mult' => '5' }])
    assert_equal [{ interface: 'eth1', peer: '10.0.0.2', local: '10.0.0.1', desired_min_tx: 100_000, detect_mult: 5 }],
                 c.sessions
  end

  # routescope docs/design/protocol-conventions.md, part 6: unknown keys
  # are refused by name.
  def test_unknown_keys_are_refused_by_name
    e = assert_raise(Config::Error) { Config.new('sesions' => []) }
    assert_equal 'unknown key sesions', e.message
    e = assert_raise(Config::Error) do
      Config.new('sessions' => [{ 'interface' => 'eth1', 'peer' => 'p', 'local' => 'l', 'interval' => 3 }])
    end
    assert_equal 'unknown session key interval', e.message
  end

  def test_a_session_needs_its_key
    assert_raise(Config::Error) { Config.session('peer' => '10.0.0.2', 'local' => '10.0.0.1') }
    assert_raise(Config::Error) { Config.session('interface' => 'e', 'peer' => 'p', 'local' => 'l', 'detect_mult' => 'x') }
  end

  def test_the_file
    Tempfile.create(%w[bfdd4r .yml]) do |f|
      f.write("socket: '@other'\nsessions:\n  - {interface: lo, peer: 127.0.0.2, local: 127.0.0.1}\n")
      f.flush
      c = Config.load(f.path)
      assert_equal ['@other', 'lo'], [c.socket, c.sessions[0][:interface]]
    end
    assert_raise(Config::Error) { Config.load('/nonexistent/bfdd4r.yml') }
  end

  def test_not_a_mapping
    assert_raise(Config::Error) { Config.new([1]) }
    assert_raise(Config::Error) { Config.new('sessions' => [1]) }
  end

  def test_the_abstract_namespace
    assert_equal "\0bfdd4r", Config.socket_path('@bfdd4r')
    assert_equal '/run/bfdd4r.sock', Config.socket_path('/run/bfdd4r.sock')
  end
end
