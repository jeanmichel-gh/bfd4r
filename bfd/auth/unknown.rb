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

module BFD
  module Auth
    # An Authentication Section kept as it came: an Auth Type no class
    # reads (0, 6 to 255), or a section too short for its type's fields.
    # Built from octets, or a hash of type, data and, to lie, auth_len.
    class Unknown
      include Section

      HEADER = 2
      KEYS = %i[type auth_len data].freeze

      attr_reader :auth_type, :data

      def initialize(arg = nil, **fields)
        case arg
        when nil then set(**fields)
        when String then parse(arg)
        when Hash then set(**arg)
        when Unknown then parse(arg.encode)
        else raise ArgumentError, "invalid argument, #{arg.inspect}"
        end
      end

      def auth_len
        @auth_len || HEADER + @data.bytesize
      end

      def encode
        [@auth_type, auth_len].pack('CC') + @data
      end

      def to_hash
        h = { type: type_name, data: @data }
        h[:auth_len] = @auth_len unless @auth_len.nil? || @auth_len == HEADER + @data.bytesize
        h
      end

      def to_s
        format('Authentication: type %s, length: %d, data %s', @auth_type, auth_len, @data.unpack1('H*'))
      end

      private

      def parse(octets)
        @auth_type, @auth_len = octets.unpack('CC')
        @data = octets.byteslice(2..).b
      end

      def set(**fields)
        check_keys(fields, KEYS)
        @auth_type = byte!(:type, Auth.type_number(fields.fetch(:type, 0)))
        @auth_len = fields[:auth_len] && byte!(:auth_len, fields[:auth_len])
        @data = String.new(fields.fetch(:data, ''), encoding: Encoding::BINARY)
      end
    end
  end
end
