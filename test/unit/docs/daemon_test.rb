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
require 'bfd/daemon/api'
require 'bfd/daemon/events'

# docs/daemon.md lists the API's methods and the event kinds; the code
# is the measure.
class DaemonDoc_Test < Test::Unit::TestCase
  DOC = File.read(File.expand_path('../../../docs/daemon.md', __dir__))

  def test_every_method_is_in_the_table_and_no_other
    listed = DOC.scan(/^\| `([\w.]+)` \|/).flatten.sort
    assert_equal BFD::Daemon::Api.names, listed
  end

  def test_the_event_kinds
    BFD::Daemon::Events::KINDS.each { |k| assert_match(/`#{k}`/, DOC, k.to_s) }
  end
end
