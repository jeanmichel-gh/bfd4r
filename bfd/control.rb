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

require 'bfd/auth'

module BFD
  # The BFD Control packet, RFC 5880 section 4.1: the 24-octet Mandatory
  # Section, then an optional Authentication Section.
  #
  #   |Vers |  Diag   |Sta|P|F|C|A|D|M|  Detect Mult  |    Length     |
  #   |                       My Discriminator                        |
  #   |                      Your Discriminator                       |
  #   |                    Desired Min TX Interval                    |
  #   |                   Required Min RX Interval                    |
  #   |                 Required Min Echo RX Interval                 |
  #
  # Built four ways, as bgp4r's and vtep4r's classes are:
  #
  #   Control.new(state: :up, my_discr: 7, your_discr: 9)   # field values
  #   Control.new({ state: :up, my_discr: 7 })              # a hash
  #   Control.new(octets)                                   # wire bytes
  #   Control.new(other)                                    # another instance
  #
  # A String is always wire bytes. No field is a String but the trailer,
  # which goes in a hash.
  #
  # **Building is never validated.** Any version, flag, length or
  # interval goes out as asked: this library is for negative testing.
  # Only a value too wide for its field is refused, since sending another
  # value in its place would be silent. BFD::Validation holds the receive
  # rules.
  #
  # Length and the A bit are worked out unless given: Length is 24 plus
  # the Authentication Section, and A is set when there is one. Give
  # either to make a packet that lies.
  #
  # A packet read from the wire keeps every bit, and encode gives back
  # the same octets: the Length and the A bit as they came, and any
  # octets after the Authentication Section as the trailer.
  class Control
    VERSION = 1
    SIZE = 24

    # RFC 5880 4.1, State (Sta).
    STATES = %i[admin_down down init up].freeze

    # RFC 5880 4.1, Diagnostic (Diag). 9 to 31 are reserved.
    DIAGS = %i[none control_detection_time_expired echo_function_failed
               neighbor_signaled_session_down forwarding_plane_reset path_down
               concatenated_path_down administratively_down
               reverse_concatenated_path_down].freeze

    # RFC 5880 4.1: the six flag bits, in the low six bits of the second
    # octet. cpi is Control Plane Independent (C), auth_present is
    # Authentication Present (A).
    FLAGS = { poll: 0x20, final: 0x10, cpi: 0x08, auth_present: 0x04,
              demand: 0x02, multipoint: 0x01 }.freeze

    # Each integer field: its default, and the largest value it holds.
    # Intervals are in microseconds (4.1). The defaults are a Down packet
    # as RFC 5880 6.8.3 has it: no faster than one a second while not Up.
    U32 = 0xffff_ffff
    FIELDS = {
      version: [VERSION, 7], diag: [0, 31], state: [1, 3], detect_mult: [3, 0xff],
      my_discr: [0, U32], your_discr: [0, U32],
      desired_min_tx: [1_000_000, U32], required_min_rx: [1_000_000, U32],
      required_min_echo_rx: [0, U32]
    }.freeze

    # Always in to_hash; the other fields only when not their default.
    ALWAYS = %i[state my_discr your_discr desired_min_tx required_min_rx].freeze

    KEYS = (FIELDS.keys + FLAGS.keys + %i[length auth trailer]).freeze

    attr_reader(*FIELDS.keys, :auth, :trailer)

    def initialize(arg = nil, **fields)
      case arg
      when nil then set(**fields)
      when String then parse(arg)
      when Control then parse(arg.encode)
      when Hash then set(**arg)
      else raise ArgumentError, "invalid argument, #{arg.inspect}"
      end
    end

    FLAGS.each_key do |name|
      next if name == :auth_present

      define_method(:"#{name}?") { instance_variable_get(:"@#{name}") }
    end

    # The A bit as it goes out: as given or read, else set when there is an
    # Authentication Section.
    def auth_present?
      @auth_present.nil? ? !@auth.nil? : @auth_present
    end

    # The Length field as it goes out.
    def length
      @length || computed_length
    end

    # The state and diagnostic as names, or the number when it has none.
    def state_name
      STATES[@state]
    end

    def diag_name
      DIAGS[@diag] || @diag
    end

    def encode
      flags = FLAGS.sum { |name, bit| flag?(name) ? bit : 0 }
      out = [(@version << 5) | @diag, (@state << 6) | flags, @detect_mult, length,
             @my_discr, @your_discr, @desired_min_tx, @required_min_rx,
             @required_min_echo_rx].pack('CCCCN5')
      out << @auth.encode if @auth
      out << @trailer
    end

    # The Mandatory and Authentication Sections, without the trailer: what
    # RFC 5880 6.7.3 and 6.7.4 call "the entire BFD Control packet".
    def packet
      out = encode
      out.byteslice(0, out.bytesize - @trailer.bytesize)
    end

    def to_shex
      encode.unpack1('H*')
    end

    # Round trips through new. The state and diagnostic are names where
    # 4.1 gives one.
    def to_hash
      h = {}
      FIELDS.each do |name, (default, _)|
        value = instance_variable_get(:"@#{name}")
        next unless ALWAYS.include?(name) || value != default

        h[name] = case name
                  when :state then state_name
                  when :diag then diag_name
                  else value
                  end
      end
      (FLAGS.keys - [:auth_present]).each { |name| h[name] = true if flag?(name) }
      h[:auth_present] = @auth_present unless @auth_present.nil? || @auth_present == !@auth.nil?
      h[:length] = @length unless @length.nil? || @length == computed_length
      h[:auth] = @auth.to_hash if @auth
      h[:trailer] = @trailer unless @trailer.empty?
      h
    end

    # tcpdump 4.99's line for a Control packet, then the discriminators:
    #   BFDv1, Control, State Up, Flags: [Poll], length: 24, my 0x00000007, your 0x00000009
    def to_s
      flags = FLAG_NAMES.filter_map { |name, text| text if flag?(name) }
      format('BFDv%d, Control, State %s, Flags: [%s], length: %d, my 0x%08x, your 0x%08x',
             @version, STATE_NAMES[@state], flags.empty? ? 'none' : flags.join(', '),
             encode.bytesize, @my_discr, @your_discr)
    end

    # tcpdump's words for the states and flags, from its output.
    STATE_NAMES = %w[AdminDown Down Init Up].freeze
    FLAG_NAMES = { poll: 'Poll', final: 'Final', cpi: 'Control Plane Independent',
                   auth_present: 'Authentication Present', demand: 'Demand',
                   multipoint: 'Multipoint' }.freeze

    def ==(other)
      other.is_a?(Control) && encode == other.encode
    end
    alias eql? ==

    def hash
      encode.hash
    end

    # A copy whose digest is right for key, RFC 5880 6.7.3 and 6.7.4: the
    # key, padded with zeros, in the digest field, then the hash of the
    # packet in its place. A Simple Password section has no digest, so its
    # copy is the same packet.
    def signed(key)
      return Control.new(self) unless @auth.respond_to?(:compute)

      digest = @auth.compute(self, key)
      Control.new(to_hash.merge(auth: @auth.to_hash.merge(digest: digest)))
    end

    private

    def flag?(name)
      name == :auth_present ? auth_present? : instance_variable_get(:"@#{name}")
    end

    def computed_length
      SIZE + (@auth ? @auth.encode.bytesize : 0)
    end

    def parse(octets)
      raise ArgumentError, "a BFD Control packet is at least #{SIZE} octets, got #{octets.bytesize}" if octets.bytesize < SIZE

      b0, b1, @detect_mult, @length, @my_discr, @your_discr, @desired_min_tx,
        @required_min_rx, @required_min_echo_rx = octets.unpack('CCCCN5')
      @version = b0 >> 5
      @diag = b0 & 0x1f
      @state = b1 >> 6
      FLAGS.each { |name, bit| instance_variable_set(:"@#{name}", (b1 & bit) != 0) }
      rest = octets.byteslice(SIZE..)
      @auth = nil
      # The Authentication Section is there when the A bit is set and its
      # two octets of type and length came (4.1). Its size is its Auth
      # Len, at least those two octets and at most what came.
      if @auth_present && rest.bytesize >= 2
        take = rest.getbyte(1).clamp(2, rest.bytesize)
        @auth = Auth.new(rest.byteslice(0, take))
        rest = rest.byteslice(take..)
      end
      @trailer = rest.b
    end

    def set(**fields)
      unknown = fields.keys - KEYS
      raise ArgumentError, "unknown Control field #{unknown.join(', ')}" unless unknown.empty?

      FIELDS.each do |name, (default, max)|
        value = fields.fetch(name, default)
        value = STATES.index(value) || value if name == :state && value.is_a?(Symbol)
        value = DIAGS.index(value) || value if name == :diag && value.is_a?(Symbol)
        unless value.is_a?(Integer) && value.between?(0, max)
          raise ArgumentError, "#{name} #{value.inspect} does not fit (0 to #{max})"
        end

        instance_variable_set(:"@#{name}", value)
      end
      (FLAGS.keys - [:auth_present]).each { |name| instance_variable_set(:"@#{name}", fields.fetch(name, false) ? true : false) }
      @auth_present = fields.key?(:auth_present) ? (fields[:auth_present] ? true : false) : nil
      @length = fields[:length]
      unless @length.nil? || (@length.is_a?(Integer) && @length.between?(0, 0xff))
        raise ArgumentError, "length #{@length.inspect} does not fit (0 to 255)"
      end

      @auth = fields[:auth] && Auth.new(fields[:auth])
      @trailer = String.new(fields.fetch(:trailer, ''), encoding: Encoding::BINARY)
    end
  end
end
