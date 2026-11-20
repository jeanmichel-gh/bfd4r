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
    # Simple Password, RFC 5880 4.2:
    #
    #   |   Auth Type   |   Auth Len    |  Auth Key ID  |  Password...  |
    #
    # Auth Type 1. Auth Len is the password's length plus three, unless
    # given. The password "MUST be from 1 to 16 bytes" (4.2); any length
    # goes out here, for negative tests.
    #
    #   Password.new(key_id: 7, password: 'secret')
    class Password
      include Section

      TYPE = 1
      HEADER = 3
      KEYS = %i[type key_id password auth_len].freeze

      attr_reader :key_id, :password

      def initialize(arg = nil, **fields)
        case arg
        when nil then set(**fields)
        when String then parse(arg)
        when Hash then set(**arg)
        when Password then parse(arg.encode)
        else raise ArgumentError, "invalid argument, #{arg.inspect}"
        end
      end

      def auth_type
        TYPE
      end

      def auth_len
        @auth_len || HEADER + @password.bytesize
      end

      def encode
        [TYPE, auth_len, @key_id].pack('CCC') + @password
      end

      def to_hash
        h = { type: :simple_password, key_id: @key_id, password: @password }
        h[:auth_len] = @auth_len unless @auth_len.nil? || @auth_len == HEADER + @password.bytesize
        h
      end

      # As tcpdump 4.99 prints it, in one line.
      def to_s
        # Octets that are not printable ASCII are escaped, as String#dump does.
        format('Authentication: Simple Password (1), length: %d, Auth Key ID: %d, Password: %s',
               auth_len, @key_id, @password.dump[1..-2])
      end

      # nil when the section passes RFC 5880 6.7.2 for the configured
      # keys, { key_id => password }, else the reason it fails.
      def section
        '6.7.2'
      end

      def failure(_control, keys)
        password = keys[@key_id] or return "Auth Key ID #{@key_id} is not configured"
        return "Auth Len #{auth_len}, not the password's length plus three" if auth_len != password.bytesize + HEADER
        return 'the password does not match' if @password != password.b

        nil
      end

      private

      def parse(octets)
        _, @auth_len, @key_id = octets.unpack('CCC')
        @password = octets.byteslice(HEADER..).b
      end

      def set(**fields)
        check_keys(fields, KEYS)
        @key_id = byte!(:key_id, fields.fetch(:key_id, 1))
        @password = String.new(fields.fetch(:password, ''), encoding: Encoding::BINARY)
        @auth_len = fields[:auth_len] && byte!(:auth_len, fields[:auth_len])
      end
    end

    register(Password::TYPE, Password)
  end
end
