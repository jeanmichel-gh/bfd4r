require 'bfd/session'
require 'bfd/runtime/clock'
require 'bfd/runtime/scheduler'

# Two sessions joined by a link on a manual clock, as bfdd4r will run
# them: one scheduler, each session's tick at its next_due, each packet
# delivered after a delay. A direction can be cut, and every action is
# logged with its time.
class Pair
  Entry = Struct.new(:time, :who, :action)

  attr_reader :a, :b, :clock, :scheduler, :log

  def initialize(a:, b:, delay: 0.001)
    @a = a
    @b = b
    @delay = delay
    @clock = BFD::Runtime::ManualClock.new
    @scheduler = BFD::Runtime::Scheduler.new(@clock)
    @log = []
    @cut = {}
    @timers = {}
  end

  def other(session)
    session.equal?(@a) ? @b : @a
  end

  def name(session)
    session.equal?(@a) ? :a : :b
  end

  def start
    [@a, @b].each { |s| handle(s, s.start(@clock.now)) }
    self
  end

  # Packets from session's side are lost while cut.
  def cut(session, on = true)
    @cut[name(session)] = on
  end

  # Run the owner's call on session now, and handle what it answers.
  def call(session)
    handle(session, yield(session, @clock.now))
  end

  def run_until(time)
    @scheduler.run_until(time)
    self
  end

  def run_for(seconds)
    run_until(@clock.now + seconds)
  end

  def sent(session = nil)
    entries(BFD::Session::Send, session)
  end

  def changes(session = nil)
    entries(BFD::Session::StateChange, session)
  end

  def entries(kind, session)
    @log.select { |e| e.action.is_a?(kind) && (session.nil? || e.who == name(session)) }
  end

  private

  def handle(session, actions)
    actions.each do |action|
      @log << Entry.new(@clock.now, name(session), action)
      deliver(session, action.packet) if action.is_a?(BFD::Session::Send)
    end
    arm(session)
  end

  def deliver(from, packet)
    return if @cut[name(from)]

    to = other(from)
    octets = packet.encode
    @scheduler.after(@delay) { handle(to, to.receive(octets, @clock.now, ttl: 255)) }
  end

  def arm(session)
    @timers[name(session)]&.cancel
    due = session.next_due
    @timers[name(session)] = due && @scheduler.at([due, @clock.now].max) { handle(session, session.tick(@clock.now)) }
  end
end
