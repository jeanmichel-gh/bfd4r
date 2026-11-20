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
require 'bfd/daemon/core'

module BFD
  module Daemon
    # bfdd4r's one thread: it owns the Core and its scheduler, so no lock
    # guards a session (routescope docs/design/bfd.md, "Time"). Socket
    # threads only read and push packets here; the API runs its calls here
    # through on_loop.
    #
    # The loop waits on its queue until the next timer is due, never
    # sleeps, then runs what came and what is due.
    class Runner
      attr_reader :core, :scheduler

      # transport: what Core sends through. clock: a MonotonicClock unless
      # a test gives another.
      def initialize(transport:, clock: Runtime::MonotonicClock.new, random: Random.new, events: nil,
                     floor: Core::FLOOR)
        @scheduler = Runtime::Scheduler.new(clock)
        @core = Core.new(transport: transport, scheduler: @scheduler, random: random, events: events, floor: floor)
        @queue = Thread::Queue.new
        @thread = nil
      end

      def clock
        @scheduler.clock
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

      # A packet from a socket thread, run on the loop.
      def push_packet(octets, interface:, source:, ttl:)
        @queue.push([:packet, octets, interface, source, ttl])
      end

      # Runs the block on the loop with the Core and answers its value, or
      # raises what it raised.
      def on_loop(&block)
        # Inline when the loop is this thread, or not started, as in a
        # test on a manual clock.
        return block.call(@core) if @thread.nil? || Thread.current == @thread

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
        when :packet
          _, octets, interface, source, ttl = job
          @core.receive(octets, interface: interface, source: source, ttl: ttl)
        when :call
          _, block, reply = job
          begin
            reply.push([true, block.call(@core)])
          rescue StandardError => e
            reply.push([false, e])
          end
        end
      end
    end
  end
end
