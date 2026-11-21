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

require 'json'
require 'socket'
require 'bfd/daemon/config'

module BFD
  # What a router uses to ask bfdd4r for sessions and to hear what they
  # do: isisd, ospfd and bgp4rd (routescope docs/design/bfd-clients.md).
  #
  #   bfd = BFD::Client.new('isisd')
  #   bfd.want(interface: 'eth1', peer: '10.0.12.2', local: '10.0.12.1')
  #   loop do
  #     IO.select(bfd.ios, nil, nil, 0.05)    # or the router's own wait
  #     bfd.poll(clock.now).each { |e| ... }  # e.type, e.state, e.failure?
  #   end
  #
  # It never blocks and keeps no thread, so a router with one loop calls
  # poll from it, and a router with threads calls it from one of them.
  # It is told the time, as protocol code is (CLAUDE.md, "Time and
  # execution").
  #
  # It holds two connections to bfdd4r: one for calls, and one that
  # events.subscribe turns into a stream. When bfdd4r is not there, or
  # goes, poll tries again every retry seconds, and on connecting asks
  # again for every session the router wants. A session outlives its
  # client's connection, so asking again is harmless.
  class Client
    # What poll answers:
    #
    #   :state       a wanted session's state changed: state is :down,
    #                :init, :up or :admin_down; from is the state this
    #                client last told, nil at first
    #   :connected   bfdd4r answers; sessions are being asked for
    #   :lost        bfdd4r is not there, or went; every state is unknown
    #   :error       bfdd4r refused a call; message says why
    Event = Struct.new(:type, :interface, :peer, :state, :from, :diag, :message, keyword_init: true) do
      def up? = type == :state && state == :up

      # An Up session that went Down for a reason a router acts on (RFC
      # 5882 4.2). Not when either end is AdminDown: state is then
      # :admin_down.
      def failure? = type == :state && from == :up && state == :down
    end

    RETRY = 1.0

    attr_reader :name, :path

    # name: the client name bfdd4r keeps on each session, such as isisd.
    # socket: bfdd4r's socket; default $BFD4R_SOCKET, else @bfdd4r.
    def initialize(name, socket: nil, env: ENV, retry_after: RETRY)
      @name = name
      name_ = socket || env['BFD4R_SOCKET']
      @path = Daemon::Config.socket_path(name_.nil? || name_.empty? ? Daemon::Config::DEFAULT_SOCKET : name_)
      @retry_after = retry_after
      @wanted = {}
      @states = {}
      @pending = {}
      @id = 0
      @calls = @events = nil
      @retry_at = nil
      @away_told = false
    end

    # The session to peer on interface is wanted. Asked for now when
    # connected, else on connecting. timers: desired_min_tx,
    # required_min_rx, detect_mult, in bfdd4r's units.
    def want(interface:, peer:, local:, **timers)
      key = [interface, peer]
      params = { 'interface' => interface, 'peer' => peer, 'local' => local }
      timers.each { |k, v| params[k.to_s] = v }
      return self if @wanted[key] == params

      @wanted[key] = params
      add(key) if connected?
      self
    end

    # The session is no longer wanted. bfdd4r keeps it while another
    # client holds it.
    def drop(interface:, peer:)
      key = [interface, peer]
      return self unless @wanted.delete(key)

      @states.delete(key)
      call('session.delete', { 'interface' => interface, 'peer' => peer, 'client' => @name }, key) if connected?
      self
    end

    def wanted?(interface:, peer:) = @wanted.key?([interface, peer])

    # The last state told for a wanted session, or nil.
    def state(interface:, peer:) = @states[[interface, peer]]

    def connected? = !@events.nil?

    # The sockets to wait on.
    def ios = [@calls, @events].compact

    # Connects when it is time to, reads what bfdd4r sent, and answers
    # the events, in order.
    def poll(now)
      out = []
      connect(now, out) unless connected?
      return out unless connected?

      read(@calls, :@calls_buf, out) { |msg| reply(msg, out) } &&
        read(@events, :@events_buf, out) { |msg| event(msg, out) }
      out
    end

    # Closes the connections. With release, lets go of every wanted
    # session first, so bfdd4r takes those no one else holds down.
    def close(release: false)
      if release && connected?
        @wanted.each_key { |(i, p)| write(@calls, 'session.delete', 'interface' => i, 'peer' => p, 'client' => @name) }
      end
      [@calls, @events].each { |s| s&.close rescue nil }
      @calls = @events = nil
      nil
    end

    # The state a session event's data says, as a client sees it: Down
    # because the peer is AdminDown is :admin_down (RFC 5882 4.2).
    def self.state_of(data)
      to = data['to'].to_s.to_sym
      return :admin_down if to == :down && data['remote_state'].to_s == 'admin_down'

      to
    end

    private

    def connect(now, out)
      return if @retry_at && now < @retry_at

      @calls = UNIXSocket.new(@path)
      @events = UNIXSocket.new(@path)
      @calls_buf = String.new
      @events_buf = String.new
      @pending.clear
      @away_told = false
      write(@events, 'events.subscribe', 'kinds' => %w[session overflow])
      out << Event.new(type: :connected, message: "bfdd4r answers on #{shown_path}")
      @wanted.each_key { |key| add(key) }
    rescue SystemCallError => e
      close
      @retry_at = now + @retry_after
      unless @away_told
        @away_told = true
        out << Event.new(type: :lost, message: "no bfdd4r on #{shown_path}: #{e.message}")
      end
    end

    def add(key)
      call('session.add', @wanted[key].merge('client' => @name), key)
    end

    def call(method, params, key)
      id = write(@calls, method, params)
      @pending[id] = [method, key] if id
    end

    def write(sock, method, params)
      @id += 1
      sock.write_nonblock("#{JSON.generate(id: @id, method: method, params: params)}\n")
      @id
    rescue IO::WaitWritable, SystemCallError, IOError
      nil
    end

    # Reads every whole line waiting on sock. Answers false when the
    # connection went, after telling so.
    def read(sock, buf_name, out)
      buf = instance_variable_get(buf_name)
      loop do
        chunk = sock.read_nonblock(65_536, exception: false)
        break if chunk == :wait_readable
        return lost(out, 'bfdd4r closed the connection') if chunk.nil?

        buf << chunk
      end
      while (nl = buf.index("\n"))
        line = buf.slice!(0, nl + 1)
        msg = begin
          JSON.parse(line)
        rescue JSON::ParserError
          next
        end
        yield msg
      end
      true
    rescue SystemCallError, IOError => e
      lost(out, "lost the connection to bfdd4r: #{e.message}")
    end

    def lost(out, message)
      close
      @states.clear
      @retry_at = nil
      @away_told = true
      out << Event.new(type: :lost, message: message)
      false
    end

    # A reply on the calls connection.
    def reply(msg, out)
      method, key = @pending.delete(msg['id'])
      return unless method

      if msg['error']
        interface, peer = key
        out << Event.new(type: :error, interface: interface, peer: peer, message: "#{method}: #{msg['error']}")
      elsif method == 'session.add' && @wanted.key?(key) && !@states.key?(key)
        # The state when it was asked for. An event on the stream may
        # already have told a later one, so this is only a first value.
        tell(key, msg['result']['state'].to_s.to_sym, nil, out)
      elsif method == 'show.sessions'
        Array(msg['result']).each do |row|
          key = [row['interface'], row['peer']]
          tell(key, row['state'].to_s.to_sym, nil, out) if @wanted.key?(key)
        end
      end
    end

    # A line on the events connection.
    def event(msg, out)
      e = msg['event'] or return
      case e['kind']
      when 'session'
        data = e['data'] || {}
        key = [data['interface'], data['peer']]
        tell(key, Client.state_of(data), data['diag'], out) if @wanted.key?(key)
      when 'overflow'
        # Events were lost: ask for every state again.
        call('show.sessions', {}, nil)
      end
    end

    def tell(key, state, diag, out)
      from = @states[key]
      return if from == state

      @states[key] = state
      out << Event.new(type: :state, interface: key[0], peer: key[1], state: state, from: from,
                       diag: diag&.to_sym)
    end

    def shown_path
      @path.start_with?("\0") ? "@#{@path[1..]}" : @path
    end
  end
end
