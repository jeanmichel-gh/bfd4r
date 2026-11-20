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

require 'bfd/runtime/clock'

module BFD
  # Where log lines go, as bgp4r's and vtep4r's Logging: a logger is a
  # plain callable, ->(level, message). Not Ruby's Logger, which Ruby 4.0
  # made a bundled gem, so bfd4r keeps no runtime gem.
  module Logging
    LEVELS = %i[debug info warn error fatal].freeze

    module_function

    # A callable that writes "TIME LEVEL message" lines to io from level
    # up. "-" is standard output. The time is the clock's wall time.
    def to_io(io, level: :info, clock: Runtime::MonotonicClock.new)
      raise ArgumentError, "log level #{level.inspect}: one of #{LEVELS.join(', ')}" unless LEVELS.include?(level)

      out = io == '-' ? $stdout : io
      out = File.open(out, 'a') if out.is_a?(String)
      out.sync = true if out.respond_to?(:sync=)
      floor = LEVELS.index(level)
      lock = Mutex.new
      lambda do |lvl, message|
        next if LEVELS.index(lvl).to_i < floor

        line = "#{clock.wall.utc.strftime('%Y-%m-%dT%H:%M:%S.%LZ')} #{lvl.to_s.upcase} #{message}\n"
        lock.synchronize { out.write(line) }
      end
    end

    # Nowhere.
    def null
      ->(_level, _message) {}
    end
  end
end
