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
  # The Authentication Section of a Control packet, RFC 5880 4.1 to 4.4:
  #
  #   |   Auth Type   |   Auth Len    |    Authentication Data...     |
  #
  # Auth.new finds the class for a section through the registry, by Auth
  # Type: from wire bytes, from a hash with :type, or from another
  # section. A type it does not know, or a section too short for its
  # type's fields, is kept whole as Auth::Unknown and sent back as it came.
  #
  #   BFD::Auth.new(octets)
  #   BFD::Auth.new(type: :meticulous_keyed_sha1, key_id: 7, sequence: 1)
  #   BFD::Auth.new(other)
  module Auth
    # RFC 5880 4.1, Auth Type. 0 and 6 to 255 are reserved.
    TYPES = { simple_password: 1, keyed_md5: 2, meticulous_keyed_md5: 3,
              keyed_sha1: 4, meticulous_keyed_sha1: 5 }.freeze

    REGISTRY = {}

    module_function

    # klass reads sections of type, an integer.
    def register(type, klass)
      REGISTRY[type] = klass
    end

    # The type's name, or its number when it has none.
    def type_name(type)
      TYPES.key(type) || type
    end

    def type_number(type)
      type.is_a?(Symbol) ? TYPES.fetch(type) { raise ArgumentError, "unknown Auth Type #{type.inspect}" } : type
    end

    def new(arg)
      case arg
      when String then from_octets(arg)
      when Hash then from_hash(arg)
      else
        raise ArgumentError, "invalid argument, #{arg.inspect}" unless arg.respond_to?(:encode) && arg.respond_to?(:auth_type)

        from_octets(arg.encode)
      end
    end

    def from_octets(octets)
      raise ArgumentError, "an Authentication Section is at least 2 octets, got #{octets.bytesize}" if octets.bytesize < 2

      klass = REGISTRY[octets.getbyte(0)]
      klass && octets.bytesize >= klass::HEADER ? klass.new(octets) : Unknown.new(octets)
    end

    def from_hash(hash)
      raise ArgumentError, 'an Authentication Section hash needs :type' unless hash.key?(:type)

      # A hash with :data is a section kept whole, whatever its type.
      klass = hash.key?(:data) ? Unknown : REGISTRY[type_number(hash[:type])] || Unknown
      klass.new(hash)
    end

    # Sections share these.
    module Section
      def to_shex
        encode.unpack1('H*')
      end

      def ==(other)
        other.respond_to?(:auth_type) && other.respond_to?(:encode) && encode == other.encode
      end
      alias_method :eql?, :==

      def hash
        encode.hash
      end

      def type_name
        Auth.type_name(auth_type)
      end

      private

      def byte!(name, value, max = 0xff)
        raise ArgumentError, "#{name} #{value.inspect} does not fit (0 to #{max})" unless value.is_a?(Integer) && value.between?(0, max)

        value
      end

      def check_keys(fields, keys)
        unknown = fields.keys - keys
        raise ArgumentError, "unknown #{self.class.name} field #{unknown.join(', ')}" unless unknown.empty?
      end
    end
  end
end

require 'bfd/auth/unknown'
require 'bfd/auth/password'
require 'bfd/auth/keyed'
