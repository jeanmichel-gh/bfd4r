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

module BFD
  # The faults a single packet cannot show: a peer that misbehaves over
  # time. A Behaviour is that peer. It runs a correct Session inside and
  # changes what the session sends, or acts on it, as its script says.
  # It answers the calls a Session does, so whatever runs sessions (a
  # test's Pair, the functional tier, later bfd4r-sim) runs it the same.
  #
  #   peer = Behaviour.new(:silent, local_discr: 9)
  #   peer.start(now)                # => what the peer sends
  #   peer.receive(packet, now)
  #   peer.tick(peer.next_due)
  #
  # Each script's timing counts from the moment the peer's session first
  # comes Up, as "after", in seconds.
  #
  # bfd4r-sim switches a running session to a script: session: is that
  # session, and adopt(now) starts the script on it. Its timing counts
  # from then if the session is already Up.
  class Behaviour
    # name: [what the peer does, what RFC 5880 expects of the session it
    # talks to, the section]
    SCRIPTS = {
      silent: ['stops sending 1 s after Up', 'Down, diagnostic 1, after the Detection Time', '6.8.4'],
      no_final: ['never answers a Poll', 'the Poll Sequence keeps going; the old interval holds', '6.8.3'],
      fast_while_down: ['holds Down and sends every 100 ms', 'we stay in Init at our own pace, one a second', '6.2, 6.8.3'],
      admin_down: ['goes AdminDown 1 s after Up', 'Down, diagnostic 3, which is not a failure', '6.8.6; RFC 5882 4.2'],
      flap: ['AdminDown and back every second', 'each change reported', '6.8.6'],
      discr_change: ['changes My Discriminator 1 s after Up', 'the session stays Up', '6.3'],
      skip_init: ['answers Down with Up', 'we stay Down', '6.2, 6.8.6'],
      slow_rx: ['raises Required Min RX to 1 s, 1 s after Up', 'we send slower from the next packet', '6.8.7']
    }.freeze

    # The peer's own session, which a test reads to see where it stands.
    attr_reader :name, :session

    def initialize(name, after: 1.0, session: nil, **session_options)
      raise ArgumentError, "unknown behaviour #{name.inspect}, one of #{SCRIPTS.keys.join(', ')}" unless SCRIPTS.key?(name)

      @name = name
      @after = after
      @session = session || Session.new(**session_options)
      @up_at = nil
      @events = []
      @fast_next = nil
      @discr = nil
      @silent = false
    end

    def description
      SCRIPTS[@name][0]
    end

    def expect
      SCRIPTS[@name][1]
    end

    def rfc
      "RFC 5880 #{SCRIPTS[@name][2]}"
    end

    def local_discr
      @discr || @session.local_discr
    end

    def session_state
      @session.session_state
    end

    def start(now)
      @fast_next = now if @name == :fast_while_down
      outgoing(@session.start(now), now)
    end

    # Takes over a running session: what start is for a new one.
    def adopt(now)
      @fast_next = now if @name == :fast_while_down
      outgoing([], now)
    end

    def next_due
      [@session.next_due, @events.first&.first, @fast_next].compact.min
    end

    def tick(now)
      out = @session.tick(now)
      while (event = @events.first) && event[0] <= now
        @events.shift
        out += event[1].call(now)
      end
      if @fast_next && now >= @fast_next
        out << Session::Send.new(@session.build)
        @fast_next = now + 0.1
      end
      outgoing(out, now)
    end

    def receive(packet, now, **opts)
      packet = Control.new(packet) if packet.is_a?(String)
      # discr_change: the peer still answers to its old discriminator.
      packet = Control.new(packet.to_hash.merge(your_discr: @session.local_discr)) if @discr && packet.your_discr == @discr
      outgoing(@session.receive(packet, now, **opts), now)
    end

    private

    # What the script does to the session's actions, and the events it
    # sets the first time the session comes Up.
    def outgoing(actions, now)
      if @up_at.nil? && @session.up?
        @up_at = now
        script_events
      end
      actions.filter_map do |action|
        next action unless action.is_a?(Session::Send)

        packet = action.packet
        case @name
        when :silent then next nil if @silent
        when :no_final then next nil if packet.final?
        when :skip_init then packet = Control.new(packet.to_hash.merge(state: :up)) if packet.state_name != :admin_down
        # 6.2: a system MAY hold a session Down; this one says Down
        # whatever its session thinks.
        when :fast_while_down then packet = Control.new(packet.to_hash.merge(state: :down))
        when :discr_change then packet = Control.new(packet.to_hash.merge(my_discr: @discr)) if @discr
        end
        Session::Send.new(packet)
      end
    end

    def script_events
      t = @up_at + @after
      case @name
      when :silent
        @events << [t, lambda { |_now|
          @silent = true
          []
        }]
      when :admin_down
        @events << [t, ->(now) { @session.admin_down(now) }]
      when :flap
        10.times do |i|
          @events << [t + i, i.even? ? ->(now) { @session.admin_down(now) } : ->(now) { @session.enable(now) }]
        end
      when :discr_change
        @events << [t, lambda { |_now|
          @discr = @session.local_discr ^ 0x0101_0101
          []
        }]
      when :slow_rx
        @events << [t, ->(now) { @session.set(now, required_min_rx: 1_000_000) }]
      end
    end
  end
end
