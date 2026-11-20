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

# The BFD packets of a capture: each UDP payload to port 3784 in a pcap
# of Ethernet, IPv4 and UDP, as tcpdump -w writes on Linux, with its
# source and TTL. Only what the fixtures need: no VLAN, no IPv6.
module Pcap
  Packet = Struct.new(:source, :ttl, :payload)

  module_function

  def bfd(path)
    data = File.binread(path)
    off = 24
    out = []
    while off < data.bytesize
      incl = data.byteslice(off + 8, 4).unpack1('V')
      frame = data.byteslice(off + 16, incl)
      off += 16 + incl
      ip = frame.byteslice(14..)
      ihl = (ip.getbyte(0) & 0x0f) * 4
      udp = ip.byteslice(ihl..)
      next unless ip.getbyte(9) == 17 && udp.unpack('nn')[1] == 3784

      out << Packet.new(ip.byteslice(12, 4).bytes.join('.'), ip.getbyte(8), udp.byteslice(8..))
    end
    out
  end
end
