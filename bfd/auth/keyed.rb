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

require 'digest'

module BFD
  module Auth
    # Keyed and Meticulous Keyed MD5 and SHA1, RFC 5880 4.3 and 4.4:
    #
    #   |   Auth Type   |   Auth Len    |  Auth Key ID  |   Reserved    |
    #   |                        Sequence Number                        |
    #   |                   Auth Key/Digest (or Hash)...                |
    #
    # Md5 is Auth Type 2, or 3 when meticulous, and Auth Len 24. Sha1 is
    # 4, or 5, and Auth Len 28. Auth Len is worked out unless given, and
    # the digest is all zeros unless given: Control#signed puts the right
    # one in. A wrong one, of any length, goes out as asked.
    #
    #   Sha1.new(key_id: 7, sequence: 1, meticulous: true)
    #   Auth.new(type: :meticulous_keyed_sha1, key_id: 7, sequence: 1)
    class Keyed
      include Section

      HEADER = 8
      KEYS = %i[type meticulous key_id reserved sequence digest auth_len].freeze

      attr_reader :key_id, :reserved, :sequence, :digest

      def initialize(arg = nil, **fields)
        case arg
        when nil then set(**fields)
        when String then parse(arg)
        when Hash then set(**arg)
        when self.class then parse(arg.encode)
        else raise ArgumentError, "invalid argument, #{arg.inspect}"
        end
      end

      def meticulous?
        @meticulous
      end

      def auth_type
        self.class::TYPES[@meticulous ? 1 : 0]
      end

      def auth_len
        @auth_len || HEADER + @digest.bytesize
      end

      def encode
        [auth_type, auth_len, @key_id, @reserved, @sequence].pack('CCCCN') + @digest
      end

      def to_hash
        h = { type: type_name, key_id: @key_id, sequence: @sequence, digest: @digest }
        h[:reserved] = @reserved unless @reserved.zero?
        h[:auth_len] = @auth_len unless @auth_len.nil? || @auth_len == HEADER + @digest.bytesize
        h
      end

      # As tcpdump 4.99 prints it, in one line.
      def to_s
        format('Authentication: %s (%d), length: %d, Auth Key ID: %d, Sequence Number: 0x%08x, %s: %s',
               self.class::LABEL[@meticulous ? 1 : 0], auth_type, auth_len, @key_id, @sequence,
               self.class::DIGEST_WORD, @digest.unpack1('H*'))
      end

      # The digest of control with key in the digest field, padded with
      # zeros to the digest's size (6.7.3, 6.7.4). A key longer than that
      # cannot be put in the field.
      def compute(control, key)
        size = self.class::SIZE
        key = key.b
        raise ArgumentError, "a #{self.class::LABEL[0]} key is at most #{size} octets, got #{key.bytesize}" if key.bytesize > size

        with_key = Control.new(control.to_hash.merge(auth: to_hash.merge(digest: key.ljust(size, "\0"))))
        self.class::DIGEST.digest(with_key.packet)
      end

      # nil when the section passes RFC 5880 6.7.3 or 6.7.4 for the
      # configured keys, { key_id => key }, else the reason it fails. The
      # sequence number window needs the session's bfd.RcvAuthSeq and is
      # the session's to check.
      def section
        self.class::SECTION
      end

      def failure(control, keys)
        key = keys[@key_id] or return "Auth Key ID #{@key_id} is not configured"
        want = HEADER + self.class::SIZE
        return "Auth Len #{auth_len}, not #{want}" if auth_len != want
        return "the digest does not match" if @digest != compute(control, key)

        nil
      end

      private

      def parse(octets)
        type, @auth_len, @key_id, @reserved, @sequence = octets.unpack('CCCCN')
        @meticulous = type == self.class::TYPES[1]
        @digest = octets.byteslice(HEADER..).b
      end

      def set(**fields)
        check_keys(fields, KEYS)
        @meticulous = if fields.key?(:type)
                        Auth.type_number(fields[:type]) == self.class::TYPES[1]
                      else
                        fields.fetch(:meticulous, false) ? true : false
                      end
        @key_id = byte!(:key_id, fields.fetch(:key_id, 1))
        @reserved = byte!(:reserved, fields.fetch(:reserved, 0))
        @sequence = byte!(:sequence, fields.fetch(:sequence, 0), 0xffff_ffff)
        @digest = String.new(fields.fetch(:digest, "\0" * self.class::SIZE), encoding: Encoding::BINARY)
        @auth_len = fields[:auth_len] && byte!(:auth_len, fields[:auth_len])
      end
    end

    # RFC 5880 4.3: Auth Type 2 or 3, a 16-octet digest.
    class Md5 < Keyed
      TYPES = [2, 3].freeze
      SIZE = 16
      DIGEST = Digest::MD5
      SECTION = '6.7.3'
      LABEL = ['Keyed MD5', 'Meticulous Keyed MD5'].freeze
      DIGEST_WORD = 'Digest'
    end

    # RFC 5880 4.4: Auth Type 4 or 5, a 20-octet hash.
    class Sha1 < Keyed
      TYPES = [4, 5].freeze
      SIZE = 20
      DIGEST = Digest::SHA1
      SECTION = '6.7.4'
      LABEL = ['Keyed SHA1', 'Meticulous Keyed SHA1'].freeze
      DIGEST_WORD = 'Hash'
    end

    Md5::TYPES.each { |type| register(type, Md5) }
    Sha1::TYPES.each { |type| register(type, Sha1) }
  end
end
