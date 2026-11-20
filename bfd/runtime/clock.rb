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

module BFD
  module Runtime
    # Copied from isis, lib/isis/runtime/clock.rb, so time works the same
    # in every protocol (routescope docs/design/protocol-conventions.md,
    # part 8).
    #
    # Protocol time. Every holding time, lifetime and interval in bfd4r is
    # measured against one of these, never against the system clock
    # directly, so a test can run protocol time without real waiting.
    #
    # A clock answers #now: seconds as a Float, monotonic, with an origin
    # that means nothing. Only differences between two readings are
    # meaningful.
    #
    # A clock also answers #wall, a Time for log lines and nothing else.
    # Wall time never decides anything in the protocol; it comes through
    # the clock only so the source scan can keep protocol code off the
    # system clock.

    # The real clock: the operating system's monotonic clock.
    #
    # This file is the one place in bfd/ allowed to read the system
    # clock. The source scan in test/unit/runtime/time_guard_test.rb holds
    # it to that.
    class MonotonicClock
      def now
        Process.clock_gettime(Process::CLOCK_MONOTONIC)
      end

      # The system's wall clock, for log lines only.
      def wall
        Time.now
      end
    end

    # A clock that moves only when told to. Tests and simulations use it,
    # usually through Scheduler#run_until, which advances it timer by timer.
    class ManualClock
      # Wall time is +wall_start+ plus the simulated seconds, so a simulated
      # run logs the same times every time it runs.
      WALL_START = Time.utc(2026, 1, 1)

      def initialize(start = 0.0, wall_start: WALL_START)
        @now = Float(start)
        @wall_start = wall_start
      end

      def now
        @now
      end

      def wall
        @wall_start + @now
      end

      # Move forward by +seconds+. A monotonic clock cannot go back, so a
      # negative step is refused rather than applied.
      def advance(seconds)
        seconds = Float(seconds)
        raise ArgumentError, "a monotonic clock cannot go back (#{seconds})" if seconds.negative?

        @now += seconds
      end

      # Move to an absolute reading, which must not be earlier than now.
      def set(time)
        time = Float(time)
        raise ArgumentError, "a monotonic clock cannot go back (#{time} < #{@now})" if time < @now

        @now = time
      end
    end
  end
end
