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

require 'bfd/session'
require 'bfd/daemon/events'

module BFD
  module Daemon
    # bfdd4r's sessions, without sockets or threads: the part a test runs
    # on a manual clock. The program (bfdd4r) wraps it with an event loop,
    # the API and UDP sockets.
    #
    # - A session is keyed by interface and peer address: one hop, so the
    #   hop count is always 1. Clients that ask for the same key share it
    #   (RFC 5882 4.4): each adds a reference, and the session goes when
    #   the last lets go.
    # - Every session runs on one scheduler. Core arms a timer at each
    #   session's next_due, as test/support/pair.rb does.
    # - A received packet is demultiplexed as RFC 5880 6.8.6 says: by Your
    #   Discriminator when it is nonzero, else by interface and source
    #   address. A packet for no session is discarded and counted.
    # - What the sessions send goes to the transport, which answers
    #   deliver(octets, interface:, peer:, local:).
    #
    #   core = Core.new(transport: t, scheduler: s)
    #   core.add(interface: 'eth1', peer: '10.0.0.2', local: '10.0.0.1', client: 'isisd')
    #   core.receive(octets, interface: 'eth1', source: '10.0.0.2', ttl: 255)
    class Core
      # The defaults of routescope docs/design/bfd.md: FRR's, 300 ms x 3.
      DEFAULTS = { desired_min_tx: 300_000, required_min_rx: 300_000, detect_mult: 3 }.freeze
      # The least Desired Min TX and Required Min RX a client may ask
      # for, by default. 300 ms held for an hour with every core busy;
      # 50, 100 and 200 ms did not (docs/timing.md). bfdd4r's file may
      # lower it, to measure or on a router with cores to spare.
      FLOOR = 300_000

      # One session and what the daemon keeps about it.
      class Entry
        attr_reader :key, :local, :session, :clients, :counters
        attr_accessor :timer, :since, :retire_at

        def initialize(key, local, session, now)
          @key = key
          @local = local
          @session = session
          @clients = []
          @counters = { packets_in: 0, packets_out: 0, flaps: 0, discards: Hash.new(0) }
          @since = now
          @timer = nil
          @retire_at = nil
        end

        def interface
          @key[0]
        end

        def peer
          @key[1]
        end

        def name
          "#{interface} #{peer}"
        end
      end

      attr_reader :events, :counters, :floor

      def initialize(transport:, scheduler:, random: Random.new, events: nil, floor: FLOOR)
        raise ArgumentError, "floor #{floor.inspect} is not a positive number of microseconds" unless floor.is_a?(Integer) && floor.positive?

        @floor = floor
        @transport = transport
        @scheduler = scheduler
        @random = random
        @events = events || Events.new(clock: -> { scheduler.clock.wall })
        @entries = {}
        @by_discr = {}
        # Packets for no session, by why.
        @counters = { no_session: Hash.new(0) }
      end

      def now
        @scheduler.now
      end

      # A session for client to peer on interface, or a reference to the
      # one there is. Its timers come from the first client to ask;
      # session.set changes them. Answers the Entry.
      def add(interface:, peer:, local:, client:, **timers)
        key = [interface, peer]
        entry = @entries[key]
        if entry.nil?
          entry = create(key, local, timers)
          @events.publish(:config, "session #{entry.name} added for #{client}", session: entry.name,
                                                                                 data: { client: client })
        end
        if entry.retire_at
          # Asked for again while it was going: it stays, and comes back.
          entry.retire_at = nil
          run(entry) { |s, t| s.enable(t) }
        end
        entry.clients << client unless entry.clients.include?(client)
        entry
      end

      # Client lets go of the session. The last one takes it to AdminDown,
      # sent for a Detection Time (RFC 5880 6.8.16), and then it goes.
      def delete(interface:, peer:, client:)
        entry = fetch(interface, peer)
        entry.clients.delete(client)
        return entry unless entry.clients.empty?

        run(entry) { |s, t| s.admin_down(t) }
        entry.retire_at = now + [(entry.session.detection_time || 0) / 1e6, 1.0].max
        @events.publish(:config, "session #{entry.name} removed by #{client}", session: entry.name,
                                                                               data: { client: client })
        arm(entry)
        entry
      end

      # AdminDown (down: true) or back (6.8.16).
      def admin(interface:, peer:, down:)
        entry = fetch(interface, peer)
        run(entry) { |s, t| down ? s.admin_down(t) : s.enable(t) }
        entry
      end

      # New timers for a live session (6.8.10 to 6.8.12).
      def set(interface:, peer:, **timers)
        entry = fetch(interface, peer)
        check_timers(timers)
        run(entry) { |s, t| s.set(t, **timers) }
        entry
      end

      # A packet that came in on interface from source. ttl is the received
      # TTL or Hop Limit.
      def receive(octets, interface:, source:, ttl:)
        entry = demux(octets, interface, source)
        return nil unless entry

        entry.counters[:packets_in] += 1
        run(entry) { |s, t| s.receive(octets, t, ttl: ttl, payload: octets.bytesize) }
        entry
      end

      def entries
        @entries.values
      end

      def entry(interface:, peer:)
        @entries[[interface, peer]]
      end

      # One row per session: every 6.8.1 variable by its RFC name, the
      # negotiated intervals, and what the daemon counts.
      def show
        entries.map do |e|
          s = e.session
          { interface: e.interface, peer: e.peer, local: e.local, clients: e.clients.dup,
            state: s.session_state, variables: s.variables, tx_interval: s.tx_interval,
            detection_time: s.detection_time, polling: s.polling?, since: e.since,
            in_state: now - e.since, packets_in: e.counters[:packets_in], packets_out: e.counters[:packets_out],
            flaps: e.counters[:flaps], discards: e.counters[:discards].to_h }
        end
      end

      private

      def fetch(interface, peer)
        @entries[[interface, peer]] or raise ArgumentError, "no session to #{peer} on #{interface}"
      end

      def create(key, local, timers)
        timers = DEFAULTS.merge(timers)
        check_timers(timers)
        session = Session.new(local_discr: new_discr, random: @random, **timers)
        entry = Entry.new(key, local, session, now)
        @entries[key] = entry
        @by_discr[session.local_discr] = entry
        run(entry) { |s, t| s.start(t) }
        entry
      end

      def check_timers(timers)
        unknown = timers.keys - DEFAULTS.keys
        raise ArgumentError, "unknown timer #{unknown.join(', ')}; timers: #{DEFAULTS.keys.join(', ')}" unless unknown.empty?

        %i[desired_min_tx required_min_rx].each do |k|
          next unless timers.key?(k)
          raise ArgumentError, "#{k} #{timers[k]} is under the floor of #{@floor} microseconds" if timers[k] < @floor
        end
      end

      # 6.8.1: unique on the system, nonzero, random.
      def new_discr
        loop do
          d = @random.rand(0xffff_ffff) + 1
          return d unless @by_discr.key?(d)
        end
      end

      # 6.8.6: by Your Discriminator when nonzero, else by where it came
      # from. What cannot be read is left to the session found by where it
      # came from, which discards it for its findings.
      def demux(octets, interface, source)
        your = octets.bytesize >= 12 ? octets.byteslice(8, 4).unpack1('N') : 0
        entry = your.zero? ? @entries[[interface, source]] : @by_discr[your]
        unless entry
          @counters[:no_session][your.zero? ? :unknown_peer : :your_discr_unknown] += 1
          return nil
        end
        if entry.key != [interface, source]
          # The discriminator names a session on another interface or to
          # another peer: not this one's packet.
          @counters[:no_session][:wrong_source] += 1
          return nil
        end
        entry
      end

      # Run a session call now, and act on what it answers.
      def run(entry)
        actions = yield(entry.session, now)
        actions.each { |a| act(entry, a) }
        arm(entry)
        entry
      end

      def act(entry, action)
        case action
        when Session::Send
          entry.counters[:packets_out] += 1
          @transport.deliver(action.packet.encode, interface: entry.interface, peer: entry.peer, local: entry.local)
        when Session::Discard
          action.findings.select { |f| f.action == :discard }.each { |f| entry.counters[:discards][f.name] += 1 }
        when Session::StateChange
          entry.since = now
          entry.counters[:flaps] += 1 if action.from == :up && action.to == :down
          @events.publish(:session, "#{entry.name} #{action.from} -> #{action.to} (#{action.diag})",
                          level: action.to == :down ? :warn : :info, session: entry.name,
                          data: { from: action.from, to: action.to, diag: action.diag,
                                  interface: entry.interface, peer: entry.peer })
        end
      end

      # A timer at the session's next_due, or at its retirement.
      def arm(entry)
        entry.timer&.cancel
        due = [entry.session.next_due, entry.retire_at].compact.min
        entry.timer = due && @scheduler.at([due, now].max) { fire(entry) }
      end

      def fire(entry)
        if entry.retire_at && now >= entry.retire_at
          entry.timer = nil
          @entries.delete(entry.key)
          @by_discr.delete(entry.session.local_discr)
          if @transport.respond_to?(:release)
            @transport.release(interface: entry.interface, peer: entry.peer, local: entry.local)
          end
          return
        end
        run(entry) { |s, t| s.tick(t) }
      end
    end
  end
end
