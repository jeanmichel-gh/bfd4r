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

module BFD
  module Daemon
    # BFD over UDP, one hop, RFC 5881. What Daemon::Core sends through, and
    # where its packets come from.
    #
    # - Received on port 3784 (section 4), one socket per VRF and local
    #   address a session uses, so two bfdd4r on one host, each with its
    #   own addresses, do not collide.
    # - In a VRF, the receiving socket is bound to the VRF's device with
    #   SO_BINDTODEVICE before its address: an address in a VRF cannot be
    #   bound otherwise (EADDRNOTAVAIL). Two VRFs may hold the same
    #   address, and each gets its own socket. An interface's VRF is its
    #   master when that master is a VRF, as `ip -j -d link show` says
    #   (routescope docs/design/bfd-vrf.md).
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
    #
    # bfd4r-sim uses it too, with listen: false: it binds port 3784 only
    # when told to (listen), and sends with any TTL and source port.
    class Udp
      PORT = 3784
      SOURCE_PORTS = (49_152..65_535).freeze
      MAX = 1500

      attr_accessor :on_packet

      # vrf_of: ->(interface) answering the VRF's name, or nil outside
      # one; `ip -j -d link show` when absent.
      def initialize(port: PORT, logger: nil, random: Random.new, listen: true, vrf_of: nil)
        @port = port
        @listen = listen
        @logger = logger
        @random = random
        @senders = {}
        @receivers = {}
        @threads = []
        @lock = Mutex.new
        @names = {}
        @vrf_of = vrf_of || method(:read_vrf)
        @vrfs = {}
        @closed = false
      end

      # Core's transport call. ttl and source_port are bfd4r-sim's: a
      # TTL other than 255 for this packet only, and a source port other
      # than the session's, from a socket of its own.
      def deliver(octets, interface:, peer:, local:, ttl: 255, source_port: nil)
        receiver(local, vrf(interface)) if @listen
        kept = sender(interface, peer, local)
        sock = source_port && source_port != kept.local_address.ip_port ? once(interface, local, source_port) : kept
        hops(sock, local, ttl) if ttl != 255
        sock.send(octets, 0, Addrinfo.udp(peer, @port))
      rescue SystemCallError => e
        log(:warn, "send to #{peer} on #{interface}: #{e.message}")
      ensure
        if sock && !sock.equal?(kept)
          sock.close
        elsif sock && ttl != 255
          hops(sock, local, 255)
        end
      end

      # Port 3784 on local, in interface's VRF if it is in one, for a
      # sender built with listen: false. Raises what bind raises,
      # Errno::EADDRINUSE when a bfdd4r has it.
      def listen(local, interface: nil)
        receiver(local, vrf(interface))
      end

      # The VRF an interface is in, by name, or 'default', as FRR's
      # show bfd peers names it.
      def vrf_name(interface)
        vrf(interface) || 'default'
      end

      # The session is gone: its send socket closes.
      def release(interface:, peer:, local: nil)
        _ = local
        @lock.synchronize do
          @vrfs.delete(interface)
          @senders.delete([interface, peer])
        end&.close
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

      def hops(sock, local, ttl)
        if family(local) == Socket::AF_INET6
          sock.setsockopt(Socket::IPPROTO_IPV6, Socket::IPV6_UNICAST_HOPS, ttl)
        else
          sock.setsockopt(Socket::IPPROTO_IP, Socket::IP_TTL, ttl)
        end
      end

      def once(interface, local, source_port)
        sock = Socket.new(family(local), Socket::SOCK_DGRAM)
        hops(sock, local, 255)
        bind_device(sock, interface)
        sock.bind(Addrinfo.udp(local, source_port))
        sock
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

      # The interface's VRF, read once and kept until a session on it is
      # released.
      def vrf(interface)
        return nil unless interface

        @lock.synchronize { return @vrfs[interface] if @vrfs.key?(interface) }
        v = @vrf_of.call(interface)
        @lock.synchronize { @vrfs[interface] = v }
      end

      # The master of interface when it is a VRF. iproute2 says what kind
      # of master it is (info_slave_kind); sysfs names the master but not
      # its kind.
      def read_vrf(interface)
        out = IO.popen(['ip', '-j', '-d', 'link', 'show', 'dev', interface], err: File::NULL, &:read)
        link = JSON.parse(out).first
        link['master'] if link.is_a?(Hash) && link.dig('linkinfo', 'info_slave_kind') == 'vrf'
      rescue SystemCallError, JSON::ParserError
        nil
      end

      def receiver(local, vrf = nil)
        @lock.synchronize do
          next if @receivers.key?([vrf, local]) || @closed

          sock = Socket.new(family(local), Socket::SOCK_DGRAM)
          if family(local) == Socket::AF_INET6
            sock.setsockopt(Socket::IPPROTO_IPV6, Socket::IPV6_RECVHOPLIMIT, 1)
            sock.setsockopt(Socket::IPPROTO_IPV6, Socket::IPV6_RECVPKTINFO, 1)
          else
            sock.setsockopt(Socket::IPPROTO_IP, Socket::IP_RECVTTL, 1)
            sock.setsockopt(Socket::IPPROTO_IP, Socket::IP_PKTINFO, 1)
          end
          begin
            # Refused or not, as bind: the socket closes and the error is raised.
            sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_BINDTODEVICE, vrf) if vrf
            sock.bind(Addrinfo.udp(local, @port))
          rescue SystemCallError
            sock.close
            raise
          end
          @receivers[[vrf, local]] = sock
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
