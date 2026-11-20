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
require 'bfd/runtime/scheduler'

module BFD
  module Runtime
    # One thread that owns a scheduler and whatever runs on it, as
    # bfdd4r's Daemon::Runner: socket threads push packets, other threads
    # run calls through on_loop, and nothing else touches its state.
    # bfd4r-sim runs its Injector on one.
    #
    #   loop = Loop.new(clock) { |octets, **meta| injector.receive(octets, **meta) }
    #   loop.start
    #   loop.on_loop { injector.status }
    class Loop
      attr_reader :scheduler

      def initialize(clock = MonotonicClock.new, &on_packet)
        @scheduler = Scheduler.new(clock)
        @on_packet = on_packet
        @queue = Thread::Queue.new
        @thread = nil
      end

      def start
        @thread = Thread.new { run }
        self
      end

      def stop
        @queue.push([:stop])
        @thread&.join(2) || @thread&.kill
        @thread = nil
        self
      end

      def running?
        @thread&.alive? || false
      end

      def push_packet(octets, **meta)
        @queue.push([:packet, octets, meta])
      end

      # Runs the block on the loop and answers its value, or raises what
      # it raised. Inline when the loop is this thread or not started.
      def on_loop(&block)
        return block.call if @thread.nil? || Thread.current == @thread

        reply = Thread::Queue.new
        @queue.push([:call, block, reply])
        ok, value = reply.pop
        ok ? value : raise(value)
      end

      private

      def run
        loop do
          due = @scheduler.next_due
          wait = due ? [due - @scheduler.now, 0].max : 1.0
          job = @queue.pop(timeout: wait)
          while job
            return if job[0] == :stop

            work(job)
            job = @queue.empty? ? nil : @queue.pop
          end
          @scheduler.run_due
        end
      end

      def work(job)
        case job[0]
        when :packet then @on_packet&.call(job[1], **job[2])
        when :call
          begin
            job[2].push([true, job[1].call])
          rescue StandardError => e
            job[2].push([false, e])
          end
        end
      end
    end
  end
end
