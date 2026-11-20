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

require 'socket'

module BFD
  module Daemon
    # BFD over UDP, one hop, RFC 5881. What Daemon::Core sends through, and
    # where its packets come from.
    #
    # - Received on port 3784 (section 4), one socket per local address a
    #   session uses, so two bfdd4r on one host, each with its own
    #   addresses, do not collide.
    # - Sent from a source port in 49152 to 65535, the same for the life
    #   of the session (section 4), with a TTL or Hop Limit of 255
    #   (section 5).
    # - The received TTL or Hop Limit and interface come from the packet's
    #   ancillary data: IP_RECVTTL and IP_PKTINFO, or IPV6_RECVHOPLIMIT
    #   and IPV6_RECVPKTINFO.
    # - A send socket is bound to its interface with SO_BINDTODEVICE when
    #   the process may (CAP_NET_RAW); without it, the route decides.
    #
    # on_packet is called from a reader thread with
    # (octets, interface:, source:, ttl:).
    class Udp
      PORT = 3784
      SOURCE_PORTS = (49_152..65_535).freeze
      MAX = 1500

      attr_accessor :on_packet

      def initialize(port: PORT, logger: nil, random: Random.new)
        @port = port
        @logger = logger
        @random = random
        @senders = {}
        @receivers = {}
        @threads = []
        @lock = Mutex.new
        @names = {}
        @closed = false
      end

      # Core's transport call.
      def deliver(octets, interface:, peer:, local:)
        receiver(local)
        sock = sender(interface, peer, local)
        sock.send(octets, 0, Addrinfo.udp(peer, @port))
      rescue SystemCallError => e
        log(:warn, "send to #{peer} on #{interface}: #{e.message}")
      end

      # The session is gone: its send socket closes.
      def release(interface:, peer:, local: nil)
        _ = local
        @lock.synchronize { @senders.delete([interface, peer]) }&.close
      end

      # The source port a session sends from.
      def source_port(interface:, peer:)
        @lock.synchronize { @senders[[interface, peer]] }&.local_address&.ip_port
      end

      def close
        @closed = true
        socks = @lock.synchronize { @senders.values + @receivers.values }
        socks.each { |s| s.close unless s.closed? }
        @threads.each { |t| t.join(1) || t.kill }
        self
      end

      private

      def family(address)
        Addrinfo.ip(address).ipv6? ? Socket::AF_INET6 : Socket::AF_INET
      end

      def sender(interface, peer, local)
        @lock.synchronize do
          @senders[[interface, peer]] ||= begin
            sock = Socket.new(family(local), Socket::SOCK_DGRAM)
            if family(local) == Socket::AF_INET6
              sock.setsockopt(Socket::IPPROTO_IPV6, Socket::IPV6_UNICAST_HOPS, 255)
            else
              sock.setsockopt(Socket::IPPROTO_IP, Socket::IP_TTL, 255)
            end
            bind_device(sock, interface)
            bind_source(sock, local)
            sock
          end
        end
      end

      # RFC 5881 4: a source port in 49152 to 65535, kept for the session.
      def bind_source(sock, local)
        tries = 0
        begin
          sock.bind(Addrinfo.udp(local, @random.rand(SOURCE_PORTS)))
        rescue Errno::EADDRINUSE
          retry if (tries += 1) < 50
          raise
        end
      end

      def bind_device(sock, interface)
        return unless interface && defined?(Socket::SO_BINDTODEVICE)

        sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_BINDTODEVICE, interface)
      rescue Errno::EPERM, Errno::ENODEV => e
        log(:debug, "not bound to #{interface}: #{e.message}")
      end

      def receiver(local)
        @lock.synchronize do
          next if @receivers.key?(local) || @closed

          sock = Socket.new(family(local), Socket::SOCK_DGRAM)
          if family(local) == Socket::AF_INET6
            sock.setsockopt(Socket::IPPROTO_IPV6, Socket::IPV6_RECVHOPLIMIT, 1)
            sock.setsockopt(Socket::IPPROTO_IPV6, Socket::IPV6_RECVPKTINFO, 1)
          else
            sock.setsockopt(Socket::IPPROTO_IP, Socket::IP_RECVTTL, 1)
            sock.setsockopt(Socket::IPPROTO_IP, Socket::IP_PKTINFO, 1)
          end
          sock.bind(Addrinfo.udp(local, @port))
          @receivers[local] = sock
          @threads << Thread.new(sock) { |s| read(s) }
        end
      end

      def read(sock)
        loop do
          octets, from, _flags, *controls = sock.recvmsg(MAX)
          ttl = nil
          ifindex = nil
          controls.each do |c|
            if (c.level == Socket::IPPROTO_IP && c.type == Socket::IP_TTL) ||
               (c.level == Socket::IPPROTO_IPV6 && c.type == Socket::IPV6_HOPLIMIT)
              ttl = c.data.unpack1('i')
            elsif c.level == Socket::IPPROTO_IP && c.type == Socket::IP_PKTINFO
              ifindex = c.ip_pktinfo[1]
            elsif c.level == Socket::IPPROTO_IPV6 && c.type == Socket::IPV6_PKTINFO
              ifindex = c.ipv6_pktinfo[1]
            end
          end
          @on_packet&.call(octets, interface: name_of(ifindex), source: from.ip_address.sub(/%.*\z/, ''), ttl: ttl)
        end
      rescue IOError, Errno::EBADF
        nil # closed
      rescue StandardError => e
        log(:error, "reader: #{e.class}: #{e.message}")
      end

      # An interface's name from its index, as the kernel numbers them.
      def name_of(ifindex)
        return nil unless ifindex

        @names[ifindex] ||= Socket.getifaddrs.find { |i| i.ifindex == ifindex }&.name
      end

      def log(level, message)
        @logger&.call(level, message)
      end
    end
  end
end
