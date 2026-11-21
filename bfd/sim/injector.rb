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

require 'ipaddr'
require 'bfd/version'
require 'bfd/control'
require 'bfd/session'
require 'bfd/fault'
require 'bfd/behaviour'
require 'bfd/daemon/events'

module BFD
  module Sim
    # A request the caller can fix: HTTP 400.
    class Refused < ArgumentError; end
    # A state that refuses it for now, a peer session already running:
    # HTTP 409.
    class Busy < StandardError; end

    # What bfd4r-sim does (routescope docs/design/bfd.md, "The injector"):
    # send crafted packets, run one well behaved session to a peer, and
    # switch that session to a BFD::Behaviour script.
    #
    # It runs on one thread with its scheduler, as bfdd4r's Core: the
    # HTTP API calls it through a Runtime::Loop. +transport+ answers
    # deliver(octets, interface:, peer:, local:, ttl:, source_port:) and,
    # for a peer session, listen(local): a Daemon::Udp built with
    # listen: false, or a Daemon::Loopback port in tests.
    class Injector
      # Control's fields a send may set. A send to the peer of a running
      # session takes My and Your Discriminator from it unless given.
      SEND_FIELDS = (Control::KEYS - %i[auth trailer]).map(&:to_s).freeze
      # action => the body keys it takes. Unknown keys are refused by name.
      ACTIONS = {
        'send' => %w[to ttl source_port octets] + SEND_FIELDS,
        'fault' => %w[case to my_discr your_discr],
        'peer' => %w[to desired_min_tx required_min_rx detect_mult behaviour after],
        'behave' => %w[name after],
        'stop' => %w[script]
      }.freeze
      EVENT_KINDS = %i[send fault peer behave session stop].freeze
      # The received packets kept for /api/received.
      KEPT = 100

      attr_reader :events, :local, :interface

      def initialize(transport:, scheduler:, local:, interface: nil, random: Random.new, events: nil)
        @transport = transport
        @scheduler = scheduler
        @local = local
        @interface = interface
        @random = random
        @events = events || Daemon::Events.new(clock: -> { scheduler.clock.wall }, kinds: EVENT_KINDS)
        @started = now
        @sent = { send: 0, fault: Hash.new(0), session: 0 }
        @received = { packets: 0, from_peer: 0, discards: Hash.new(0), last: [] }
        @peer = nil
      end

      def act(action, body)
        keys = ACTIONS.fetch(action) { raise Refused, "unknown action #{action}; one of #{ACTIONS.keys.join(', ')}" }
        unknown = body.keys - keys
        raise Refused, "#{action} takes #{keys.join(', ')}; not #{unknown.join(', ')}" unless unknown.empty?

        __send__("do_#{action}", body)
      end

      def status
        { version: BFD::VERSION, local: @local, interface: @interface, uptime: (now - @started).round(1),
          peer: peer_row }
      end

      def sent
        { send: @sent[:send], fault: @sent[:fault].dup, session: @sent[:session] }
      end

      def received
        { packets: @received[:packets], from_peer: @received[:from_peer], discards: @received[:discards].dup,
          last: @received[:last].dup }
      end

      # What it can send: the fault catalog and the behaviours.
      def catalog
        { actions: ACTIONS,
          faults: Fault.catalog.map { |e| e.reject { |k, _| k == :build } },
          behaviours: Behaviour::SCRIPTS.map do |name, (does, expect, rfc)|
            { name: name, description: does, expect: expect, rfc: "RFC 5880 #{rfc}" }
          end }
      end

      def events_since(params)
        n = Integer(params.fetch('since', 0))
        { seq: @events.seq, events: @events.since(n).map(&:to_h) }
      rescue ArgumentError
        raise Refused, "since: #{params['since'].inspect} is not a sequence number"
      end

      # A packet from the transport. Packets from the peer go to its
      # session; every one is counted and the last ones kept.
      def receive(octets, interface: nil, source: nil, ttl: nil)
        _ = interface
        @received[:packets] += 1
        keep(octets, source, ttl)
        return unless @peer && source == @peer[:to]

        @received[:from_peer] += 1
        handle(@peer[:runner].receive(octets, now, ttl: ttl, payload: octets.bytesize))
      end

      private

      def now
        @scheduler.now
      end

      def do_send(b)
        to = to(b)
        octets = if b.key?('octets')
                   hex(b['octets'])
                 else
                   fields = b.slice(*SEND_FIELDS).transform_keys(&:to_sym)
                   fields[:state] = fields[:state].to_sym if fields[:state].is_a?(String)
                   if @peer && to == @peer[:to]
                     fields[:my_discr] ||= @peer[:session].local_discr
                     fields[:your_discr] ||= @peer[:session].remote_discr
                   end
                   Control.new(fields).encode
                 end
        ttl = number(b, 'ttl', 0..255, 255)
        port = number(b, 'source_port', 1..65_535, nil)
        deliver(octets, to, ttl: ttl, source_port: port)
        @sent[:send] += 1
        @events.publish(:send, "send #{octets.bytesize} octets to #{to}, TTL #{ttl}",
                        data: { to: to, octets: octets.bytesize, ttl: ttl, source_port: port }.compact)
        { sent: 1, to: to, octets: octets.bytesize, ttl: ttl }
      rescue ArgumentError, KeyError => e
        raise Refused, e.message
      end

      def do_fault(b)
        name = b['case'].to_s.to_sym
        raise Refused, "case #{b['case'].inspect}: one of #{Fault.names.join(', ')}" unless Fault.names.include?(name)

        entry = Fault.entry(name)
        to = b.key?('to') ? to(b) : @peer&.fetch(:to)
        raise Refused, 'fault needs to, or a peer session (POST /api/peer)' unless to

        session = @peer && to == @peer[:to] ? @peer[:session] : nil
        my = discr(b, 'my_discr', session&.local_discr)
        your = discr(b, 'your_discr', session&.remote_discr)
        deliver(Fault.wire(name, my_discr: my, your_discr: your), to, ttl: entry[:ttl])
        @sent[:fault][name] += 1
        @events.publish(:fault, "fault #{name} to #{to}", data: { to: to, case: name, expect: entry[:expect] })
        { sent: 1, to: to, case: name, finding: entry[:finding], expect: entry[:expect], rfc: entry[:rfc],
          ttl: entry[:ttl], auth: entry[:auth] }
      end

      def do_peer(b)
        raise Busy, "a peer session to #{@peer[:to]} is running; stop it first" if @peer

        to = to(b)
        timers = %w[desired_min_tx required_min_rx detect_mult].each_with_object({}) do |k, h|
          h[k.to_sym] = number(b, k, k == 'detect_mult' ? 1..255 : 1..0xffff_ffff, nil) if b.key?(k)
        end
        name = b.key?('behaviour') ? script_name(b['behaviour']) : nil
        after = after(b)
        begin
          @transport.listen(@local) if @transport.respond_to?(:listen)
        rescue SystemCallError => e
          raise Busy, "cannot receive on #{@local} port 3784: #{e.message}; a bfdd4r there has it"
        end
        session = Session.new(random: @random, **timers)
        runner = name ? Behaviour.new(name, after: after, session: session) : session
        @peer = { to: to, session: session, runner: runner, behaviour: name, timer: nil }
        @events.publish(:peer, "peer session to #{to}#{" as #{name}" if name}",
                        data: { to: to, local_discr: session.local_discr, behaviour: name }.compact)
        handle(runner.start(now))
        peer_row
      end

      def do_behave(b)
        raise Refused, 'no peer session: POST /api/peer first' unless @peer
        raise Busy, "#{@peer[:behaviour]} is running; stop it first" if @peer[:behaviour]

        name = script_name(b['name'])
        after = after(b)
        script = Behaviour.new(name, after: after, session: @peer[:session])
        @peer[:runner] = script
        @peer[:behaviour] = name
        @events.publish(:behave, "behave #{name}: #{script.description}", data: { name: name, after: after })
        handle(script.adopt(now))
        { behaviour: name, description: script.description, expect: script.expect, rfc: script.rfc }
      end

      # Ends the script and the session; with script: true, the script
      # only, and the session goes on well behaved.
      def do_stop(b)
        return { stopped: nil } unless @peer

        if b['script']
          return { stopped: nil } unless @peer[:behaviour]

          name = @peer[:behaviour]
          @peer[:runner] = @peer[:session]
          @peer[:behaviour] = nil
          @events.publish(:stop, "behaviour #{name} stopped", data: { behaviour: name })
          arm
          return { stopped: 'script', behaviour: name }
        end
        peer = @peer
        handle(peer[:session].admin_down(now))
        peer[:timer]&.cancel
        @peer = nil
        @transport.release(interface: @interface, peer: peer[:to], local: @local) if @transport.respond_to?(:release)
        @events.publish(:stop, "peer session to #{peer[:to]} stopped", data: { to: peer[:to] })
        { stopped: 'session', to: peer[:to] }
      end

      # What the peer's session or script answers: sends, state changes
      # and discards. Then its next timer.
      def handle(actions)
        return unless @peer

        actions.each do |a|
          case a
          when Session::Send
            deliver(a.packet.encode, @peer[:to])
            @sent[:session] += 1
          when Session::StateChange
            @events.publish(:session, "#{@peer[:to]} #{a}", data: { from: a.from, to: a.to, diag: a.diag })
          when Session::Discard
            a.findings.select { |f| f.action == :discard }.each { |f| @received[:discards][f.name] += 1 }
          end
        end
        arm
        nil
      end

      def arm
        return unless @peer

        @peer[:timer]&.cancel
        due = @peer[:runner].next_due
        peer = @peer
        @peer[:timer] = due && @scheduler.at([due, now].max) do
          handle(peer[:runner].tick(now)) if @peer.equal?(peer)
        end
      end

      def deliver(octets, to, ttl: 255, source_port: nil)
        @transport.deliver(octets, interface: @interface, peer: to, local: @local, ttl: ttl, source_port: source_port)
      end

      def keep(octets, source, ttl)
        row = { from: source, ttl: ttl, octets: octets.bytesize }
        begin
          p = Control.new(octets)
          row.merge!(state: p.state_name, my_discr: p.my_discr, your_discr: p.your_discr, poll: p.poll?, final: p.final?)
        rescue StandardError
          row[:undecoded] = true
        end
        @received[:last] << row
        @received[:last].shift if @received[:last].size > KEPT
      end

      def peer_row
        return nil unless @peer

        s = @peer[:session]
        { to: @peer[:to], state: s.session_state, behaviour: @peer[:behaviour], local_discr: s.local_discr,
          remote_discr: s.remote_discr, tx_interval: s.tx_interval, detection_time: s.detection_time,
          variables: s.variables }
      end

      def to(body)
        a = body['to'] or raise Refused, 'to: the peer to send to is required'
        IPAddr.new(a.to_s)
        a.to_s
      rescue IPAddr::Error
        raise Refused, "to: #{a.inspect} is not an address"
      end

      def number(body, key, range, default)
        return default unless body.key?(key)

        v = body[key]
        raise Refused, "#{key}: #{v.inspect} is not a whole number in #{range}" unless v.is_a?(Integer) && range.cover?(v)

        v
      end

      def discr(body, key, default)
        v = body.key?(key) ? body[key] : default
        unless v.is_a?(Integer) && v.between?(0, 0xffff_ffff)
          raise Refused, "#{key}: give it, or run a peer session (POST /api/peer) to that address"
        end

        v
      end

      def script_name(text)
        name = text.to_s.to_sym
        return name if Behaviour::SCRIPTS.key?(name)

        raise Refused, "behaviour #{text.inspect}: one of #{Behaviour::SCRIPTS.keys.join(', ')}"
      end

      def after(body)
        after = body.fetch('after', 1.0)
        raise Refused, "after: #{after.inspect} is not a number of seconds" unless after.is_a?(Numeric) && after >= 0

        after.to_f
      end

      def hex(text)
        raise Refused, "octets: #{text.inspect} is not an even number of hex digits" unless text.is_a?(String) && text.match?(/\A(\h\h)*\z/)

        [text].pack('H*')
      end
    end
  end
end
