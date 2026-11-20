require 'bfd/validation'

module BFD
  # One BFD session: the state machine and timers of RFC 5880 6.8, in
  # Asynchronous mode, without authentication.
  #
  # It has no socket, thread or clock of its own. It is told the time,
  # in seconds on a monotonic clock, with each call, and answers with
  # actions: packets to send and state changes. The owner (bfdd4r, or a
  # test on a manual clock) calls tick at next_due, and receive with each
  # packet demultiplexed to the session.
  #
  #   s = Session.new(local_discr: 7, desired_min_tx: 300_000, required_min_rx: 300_000)
  #   s.start(now)                 # => [Send(Down)]
  #   s.receive(control, now)      # => [StateChange(down -> init), Send(Init)]
  #   s.tick(s.next_due)           # => [Send(...)]
  #
  # Every 6.8.1 variable is readable, by its RFC name through variables,
  # and as a method in Ruby's spelling.
  #
  # Not in this version: Demand mode (6.6), which the session never asks
  # for but honours from the remote end; the Echo function (6.4); and
  # authentication (6.7), so bfd.AuthType is 0.
  class Session
    # What the owner does: send packet, now.
    Send = Struct.new(:packet) do
      def to_s
        "send #{packet}"
      end
    end

    # A change of bfd.SessionState, with bfd.LocalDiag after it.
    StateChange = Struct.new(:from, :to, :diag) do
      def to_s
        "#{from} -> #{to} (#{diag})"
      end
    end

    # A received packet that RFC 5880 6.8.6 or RFC 5881 5 discards: a
    # Control, or the octets when they are too short to be one.
    Discard = Struct.new(:packet, :findings) do
      def to_s
        "discard: #{findings.map(&:name).join(', ')}"
      end
    end

    # RFC 5880 6.8.3: not less than one second while not Up.
    SLOW = 1_000_000

    # The 6.8.1 variables, by their RFC names, and the method for each.
    VARIABLES = {
      'bfd.SessionState' => :session_state, 'bfd.RemoteSessionState' => :remote_session_state,
      'bfd.LocalDiscr' => :local_discr, 'bfd.RemoteDiscr' => :remote_discr,
      'bfd.LocalDiag' => :local_diag, 'bfd.DesiredMinTxInterval' => :desired_min_tx_interval,
      'bfd.RequiredMinRxInterval' => :required_min_rx_interval,
      'bfd.RemoteMinRxInterval' => :remote_min_rx_interval, 'bfd.DemandMode' => :demand_mode,
      'bfd.RemoteDemandMode' => :remote_demand_mode, 'bfd.DetectMult' => :detect_mult,
      'bfd.AuthType' => :auth_type
    }.freeze

    attr_reader(*VARIABLES.values)

    # What was last heard from the remote end, which 6.8.4 needs and
    # 6.8.1 does not name: its Detect Mult and Desired Min TX Interval.
    attr_reader :remote_detect_mult, :remote_desired_min_tx

    # The configured Desired Min TX Interval, which bfd.DesiredMinTxInterval
    # takes while the session is Up.
    attr_reader :desired_min_tx

    # Clock times, in seconds: the next periodic packet, the end of the
    # Detection Time, the last packet received. nil when none.
    attr_reader :next_tx, :detect_at, :last_rx

    # local_discr       bfd.LocalDiscr, nonzero and unique on the system;
    #                   random when not given (6.8.1)
    # desired_min_tx    microseconds, used while Up
    # required_min_rx   bfd.RequiredMinRxInterval, microseconds
    # detect_mult       bfd.DetectMult
    # passive           the Passive role of 6.1: silent until the remote
    #                   end is heard
    # random            a Random, for the discriminator and the jitter
    def initialize(local_discr: nil, desired_min_tx: 300_000, required_min_rx: 300_000, detect_mult: 3,
                   passive: false, random: Random.new)
      @random = random
      @local_discr = local_discr || (@random.rand(0xffff_ffff) + 1)
      raise ArgumentError, 'bfd.LocalDiscr must be nonzero (6.8.1)' unless @local_discr.between?(1, 0xffff_ffff)
      raise ArgumentError, 'bfd.DetectMult must be nonzero (6.8.1)' unless detect_mult.between?(1, 255)

      @passive = passive
      @desired_min_tx = desired_min_tx
      @required_min_rx_interval = required_min_rx
      @detect_mult = detect_mult
      # 6.8.1, the initial values.
      @session_state = :down
      @remote_session_state = :down
      @remote_discr = 0
      @local_diag = 0
      @desired_min_tx_interval = [SLOW, desired_min_tx].max
      @remote_min_rx_interval = 1
      @demand_mode = 0
      @remote_demand_mode = 0
      @auth_type = 0
      @remote_detect_mult = nil
      @remote_desired_min_tx = nil
      # The Poll Sequence (6.5): whether one is being sent, whether
      # another waits for it to end, and the values 6.8.3 holds back
      # until it does.
      @polling = false
      @poll_waiting = false
      @final_clear_seen = false
      @tx_desired_in_use = @desired_min_tx_interval
      @rx_for_detection = @required_min_rx_interval
      @next_tx = nil
      @detect_at = nil
      @last_rx = nil
      @forget_at = nil
      @last_sent = nil
    end

    def variables
      VARIABLES.transform_values { |name| send(name) }
    end

    def polling?
      @polling
    end

    def up?
      @session_state == :up
    end

    # The interval between periodic packets before jitter, microseconds
    # (6.8.7): the greater of what we would send at and what the remote
    # end can take. Held at the old Desired Min TX while a Poll Sequence
    # for an increase runs (6.8.3).
    def tx_interval
      [@tx_desired_in_use, @remote_min_rx_interval].max
    end

    # The Detection Time, microseconds (6.8.4, Asynchronous mode), or nil
    # before the remote end is heard.
    def detection_time
      return nil unless @remote_detect_mult

      @remote_detect_mult * [@rx_for_detection, @remote_desired_min_tx].max
    end

    # The first packet. Both ends of a one-hop session are Active (RFC
    # 5881 3), and start sending at once.
    def start(now)
      @next_tx = now
      tick(now)
    end

    # The earliest time tick has something to do, or nil.
    def next_due
      [periodic? ? @next_tx : nil, @detect_at, @forget_at].compact.min
    end

    # What is due at now: the Detection Time expiring (6.8.4), state kept
    # a Detection Time after the last packet (6.8.1), and the periodic
    # packet (6.8.7).
    def tick(now)
      out = []
      if @detect_at && now >= @detect_at
        @detect_at = nil
        change(:down, 1, now, out) if %i[init up].include?(@session_state)
      end
      if @forget_at && now >= @forget_at
        # 6.8.1: bfd.RemoteDiscr is zero once a Detection Time passes
        # without a packet.
        @forget_at = nil
        @remote_discr = 0
      end
      transmit(now, out) if periodic? && @next_tx && now >= @next_tx
      out
    end

    # A packet demultiplexed to this session: RFC 5880 6.8.6 from the
    # discard rules on. ttl: the received TTL or Hop Limit, checked as
    # RFC 5881 5 says when given; payload: the octets UDP carried.
    def receive(packet, now, ttl: nil, payload: nil)
      # Checked before it is read, so octets too short to be a packet are
      # discarded, not raised on.
      findings = Validation.check(packet, payload: payload, known: [@local_discr], auth: false, ttl: ttl)
      return [Discard.new(packet, findings)] if findings.any? { |f| f.action == :discard }

      packet = Control.new(packet) if packet.is_a?(String)

      out = []
      @remote_discr = packet.my_discr
      @remote_session_state = packet.state_name
      @remote_demand_mode = packet.demand? ? 1 : 0
      old_interval = tx_interval
      @remote_min_rx_interval = packet.required_min_rx
      @remote_detect_mult = packet.detect_mult
      @remote_desired_min_tx = packet.desired_min_tx
      end_poll if @polling && packet.final?
      @final_clear_seen = true if !packet.final? && @poll_waiting && !@polling
      # Update the transmit interval (6.8.2, 6.8.3).
      shorter(old_interval, now)
      @last_rx = now
      # The packet counts as received (6.8.4), and resets the Detection
      # Time and the time state is kept (6.8.1).
      @detect_at = now + (detection_time / 1e6)
      @forget_at = @detect_at

      # 6.8.6 ends here for a session in AdminDown: the packet is
      # discarded, so no Final either, though 6.8.7 answers a Poll
      # "without respect to the session state". 6.8.6 says processing
      # MUST cease, and it is followed here.
      return out if @session_state == :admin_down

      before = @session_state
      if packet.state_name == :admin_down
        change(:down, 3, now, out) unless @session_state == :down
      else
        case @session_state
        when :down
          case packet.state_name
          when :down then change(:init, @local_diag, now, out)
          when :init then change(:up, @local_diag, now, out)
          end
        when :init
          change(:up, @local_diag, now, out) if %i[init up].include?(packet.state_name)
        when :up
          change(:down, 3, now, out) if packet.state_name == :down
        end
      end
      # A pending Poll Sequence may start once another packet with F clear
      # came after the last one ended (6.8.3, choice 3).
      start_poll(now, out) if @poll_waiting && !@polling && @final_clear_seen
      # 6.8.6: a Poll is answered with Final at once (6.8.7), unless a
      # state change has just sent a packet that can carry it.
      if packet.poll?
        if @session_state != before && out.last.is_a?(Send)
          out[-1] = Send.new(build(final: true))
        else
          out << Send.new(build(final: true))
        end
        @last_sent = now
      end
      out
    end

    # 6.8.16: AdminDown, with a diagnostic; :administratively_down unless
    # told otherwise, :path_down when the path failed.
    def admin_down(now, diag: :administratively_down)
      out = []
      code = diag.is_a?(Symbol) ? Control::DIAGS.index(diag) : diag
      change(:admin_down, code, now, out) unless @session_state == :admin_down
      out
    end

    # 6.8.16: back to Down.
    def enable(now)
      out = []
      change(:down, @local_diag, now, out) if @session_state == :admin_down
      out
    end

    # 6.8.10 to 6.8.12: new timers. A change of either interval starts a
    # Poll Sequence (6.8.3); Detect Mult does not need one.
    def set(now, desired_min_tx: nil, required_min_rx: nil, detect_mult: nil)
      out = []
      if detect_mult
        raise ArgumentError, 'bfd.DetectMult must be nonzero (6.8.12)' unless detect_mult.between?(1, 255)

        @detect_mult = detect_mult
      end
      before = [@desired_min_tx_interval, @required_min_rx_interval]
      @desired_min_tx = desired_min_tx if desired_min_tx
      @desired_min_tx_interval = effective_desired
      if required_min_rx
        # 6.8.3: a reduction while Up is not used for the Detection Time
        # until the Poll Sequence ends.
        @rx_for_detection = required_min_rx unless up? && required_min_rx < @required_min_rx_interval
        @required_min_rx_interval = required_min_rx
      end
      timers_changed(before, now, out)
      out
    end

    # The packet this session sends now (6.8.7).
    def build(final: false)
      Control.new(diag: @local_diag, state: @session_state, poll: @polling && !final, final: final,
                  detect_mult: @detect_mult, my_discr: @local_discr, your_discr: @remote_discr,
                  desired_min_tx: @desired_min_tx_interval, required_min_rx: @required_min_rx_interval,
                  required_min_echo_rx: 0)
    end

    private

    # 6.8.7: no periodic packets with the Passive role before the remote
    # end is heard, when it wants none, or while it is in Demand mode
    # and no Poll Sequence runs.
    def periodic?
      return false if @passive && @remote_discr.zero?
      return false if @remote_min_rx_interval.zero?
      return false if remote_demand_active? && !@polling

      true
    end

    def remote_demand_active?
      @remote_demand_mode == 1 && up? && @remote_session_state == :up
    end

    # The interval cut by a random 0 to 25%; with Detect Mult 1, to
    # between 75% and 90% (6.8.7). Seconds.
    def jittered(interval)
      cut = @detect_mult == 1 ? 0.10 + (@random.rand * 0.15) : @random.rand * 0.25
      interval * (1 - cut) / 1e6
    end

    def transmit(now, out)
      out << Send.new(build)
      @last_sent = now
      @next_tx = now + jittered(tx_interval)
    end

    def effective_desired
      up? ? @desired_min_tx : [SLOW, @desired_min_tx].max
    end

    def change(to, diag, now, out)
      from = @session_state
      @session_state = to
      @local_diag = diag
      out << StateChange.new(from, to, Control::DIAGS[diag] || diag)
      before = [@desired_min_tx_interval, @required_min_rx_interval]
      @desired_min_tx_interval = effective_desired
      timers_changed(before, now, out)
      # 6.8.7: a packet whose contents changed SHOULD go out between
      # periodic ones. It carries the Poll bit when the change started a
      # Poll Sequence, as BIRD's and FRR's do.
      out << Send.new(build)
      @last_sent = now
    end

    # After a change of bfd.DesiredMinTxInterval or
    # bfd.RequiredMinRxInterval: a Poll Sequence (6.8.3), and what may
    # change at once.
    def timers_changed(before, now, out)
      desired, required = before
      return if [@desired_min_tx_interval, @required_min_rx_interval] == before

      old_interval = tx_interval
      # An increase of Desired Min TX while Up waits for the Poll Sequence
      # to end; anything else applies at once (6.8.3).
      @tx_desired_in_use = @desired_min_tx_interval unless up? && @desired_min_tx_interval > desired
      @rx_for_detection = @required_min_rx_interval unless up? && @required_min_rx_interval < required
      @detect_at = @last_rx + (detection_time / 1e6) if @last_rx && @detect_at && detection_time
      shorter(old_interval, now)
      if @polling
        # 6.8.3: a second change while one Poll Sequence runs waits.
        @poll_waiting = true
        @final_clear_seen = false
      else
        start_poll(now, out)
      end
    end

    # 6.5: the Poll bit goes on the periodic packets, and no extra packet
    # is sent for it.
    def start_poll(_now, _out)
      @polling = true
      @poll_waiting = false
      @final_clear_seen = false
    end

    # 6.8.3: a shorter transmit interval is honoured at once: the next
    # packet goes no later than the new interval after the last one, or
    # now when that has passed. A longer one applies from the next packet.
    def shorter(old_interval, now)
      return unless tx_interval < old_interval && @last_sent && @next_tx

      @next_tx = [@next_tx, [now, @last_sent + jittered(tx_interval)].max].min
    end

    def end_poll
      @polling = false
      @tx_desired_in_use = @desired_min_tx_interval
      @rx_for_detection = @required_min_rx_interval
      @final_clear_seen = false
    end
  end
end
