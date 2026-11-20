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
    # Copied from isis, lib/isis/runtime/scheduler.rb.
    #
    # Callbacks due at a time on a clock. A protocol timer is a scheduled
    # callback, never a sleep.
    #
    # The scheduler never reads the system clock and never waits. Something
    # outside it decides when to call #run_due: a real event loop on a
    # MonotonicClock, or a test calling #run_until on a ManualClock, which
    # advances the clock from one due timer to the next with no real
    # waiting at all.
    #
    # Timers due at the same time run in the order they were scheduled.
    class Scheduler
      # One scheduled callback. Cancel it to stop it from running.
      class Timer
        attr_reader :due

        def initialize(due, seq, callback)
          @due = due
          @seq = seq
          @callback = callback
          @cancelled = false
        end

        def cancel
          @cancelled = true
        end

        def cancelled?
          @cancelled
        end

        def sort_key
          [@due, @seq]
        end

        def fire
          @callback.call
        end
      end

      attr_reader :clock

      def initialize(clock)
        @clock = clock
        @timers = []
        @seq = 0
      end

      def now
        @clock.now
      end

      # Run the block +delay+ seconds from now.
      def after(delay, &callback)
        delay = Float(delay)
        raise ArgumentError, "delay must not be negative (#{delay})" if delay.negative?

        at(now + delay, &callback)
      end

      # Run the block at clock time +time+. A time already past is due at
      # once, on the next #run_due.
      def at(time, &callback)
        raise ArgumentError, "a timer needs a block" unless callback

        @seq += 1
        timer = Timer.new(Float(time), @seq, callback)
        @timers << timer
        timer
      end

      # The due time of the earliest pending timer, or nil when none.
      def next_due
        pending.min_by(&:sort_key)&.due
      end

      # Number of timers not yet run or cancelled.
      def pending_count
        pending.size
      end

      # Run every timer due at or before the clock's current reading,
      # earliest first, including timers that a callback schedules inside
      # that window. Returns how many ran.
      def run_due
        ran = 0
        while (timer = take_next_due(now))
          timer.fire
          ran += 1
        end
        ran
      end

      # Advance a clock that supports #set to +time+, stopping at each due
      # timer on the way so callbacks see the clock at their own due time.
      # Returns how many timers ran.
      def run_until(time)
        time = Float(time)
        ran = 0
        while (timer = take_next_due(time))
          @clock.set(timer.due) if timer.due > now
          timer.fire
          ran += 1
        end
        @clock.set(time) if time > now
        ran
      end

      # Advance by +seconds+. Shorthand for run_until(now + seconds).
      def advance(seconds)
        run_until(now + Float(seconds))
      end

      private

      def pending
        @timers.reject!(&:cancelled?)
        @timers
      end

      def take_next_due(limit)
        timer = pending.select { |t| t.due <= limit }.min_by(&:sort_key)
        @timers.delete(timer) if timer
        timer
      end
    end
  end
end
