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

require 'test/unit'
require 'bfd/control'
require_relative '../support/pcap'

# test/fixtures/frr-bird.pcap: FRR 10.2.1's bfdd (10.99.0.10) and BIRD
# 2.0.12 (10.99.0.11) on a Docker bridge on ospflab, 2026-11-20, 300 ms
# x 3. FRR's peer was shut down and brought back during the capture, so
# it holds every state, a Poll and a Final.
class Control_Test < Test::Unit::TestCase
  include BFD

  FRR_BIRD = Pcap.bfd('test/fixtures/frr-bird.pcap')

  # BIRD, Up, at 300 ms.
  BIRD_UP = '20c0031839554fea2a99c705000493e0000493e000000000'
  # FRR, Up: Required Min Echo RX 50 ms.
  FRR_UP = '20c003182a99c70539554fea000493e0000493e00000c350'
  # BIRD, Down with diagnostic 3 and a Poll, at 1 s: FRR went AdminDown.
  BIRD_DOWN = '2360031839554fea2a99c705000f4240000493e000000000'
  # FRR, AdminDown.
  FRR_ADMIN_DOWN = '200003182a99c70539554fea000493e0000493e00000c350'

  def wire(hex)
    [hex].pack('H*')
  end

  # From the wire.

  def test_every_captured_packet_encodes_as_it_came
    assert_equal 77, FRR_BIRD.size
    FRR_BIRD.each { |pk| assert_equal pk.payload.unpack1('H*'), Control.new(pk.payload).to_shex }
  end

  def test_the_states_and_flags_in_the_capture
    seen = FRR_BIRD.map { |pk| c = Control.new(pk.payload); [c.state_name, c.poll?, c.final?] }.uniq
    assert_equal [[:admin_down, false, false], [:admin_down, false, true], [:down, false, false], [:down, true, false],
                  [:init, false, false], [:up, false, false], [:up, false, true], [:up, true, false]].sort_by(&:inspect), seen.sort_by(&:inspect)
  end

  def test_parse_birds_up
    c = Control.new(wire(BIRD_UP))
    assert_equal [1, :none, :up, 3, 24], [c.version, c.diag_name, c.state_name, c.detect_mult, c.length]
    assert_equal [0x39554fea, 0x2a99c705], [c.my_discr, c.your_discr]
    assert_equal [300_000, 300_000, 0], [c.desired_min_tx, c.required_min_rx, c.required_min_echo_rx]
    refute c.poll? || c.final? || c.cpi? || c.auth_present? || c.demand? || c.multipoint?
    assert_nil c.auth
  end

  def test_parse_frrs_up
    assert_equal 50_000, Control.new(wire(FRR_UP)).required_min_echo_rx
  end

  def test_parse_birds_down
    c = Control.new(wire(BIRD_DOWN))
    assert_equal [:down, :neighbor_signaled_session_down, 3, true], [c.state_name, c.diag_name, c.diag, c.poll?]
    assert_equal 1_000_000, c.desired_min_tx
  end

  def test_parse_frrs_admin_down
    assert_equal :admin_down, Control.new(wire(FRR_ADMIN_DOWN)).state_name
  end

  def test_fewer_than_24_octets_is_not_a_control_packet
    assert_raise(ArgumentError) { Control.new(wire(BIRD_UP[0, 46])) }
  end

  def test_the_string_is_not_consumed
    octets = wire(BIRD_UP)
    Control.new(octets)
    assert_equal BIRD_UP, octets.unpack1('H*')
  end

  # Field values and a hash.

  def test_birds_up_from_fields
    c = Control.new(state: :up, my_discr: 0x39554fea, your_discr: 0x2a99c705,
                    desired_min_tx: 300_000, required_min_rx: 300_000)
    assert_equal BIRD_UP, c.to_shex
    assert_equal BIRD_UP, Control.new({ state: :up, my_discr: 0x39554fea, your_discr: 0x2a99c705,
                                        desired_min_tx: 300_000, required_min_rx: 300_000 }).to_shex
  end

  def test_birds_down_from_fields
    c = Control.new(state: :down, diag: :neighbor_signaled_session_down, poll: true,
                    my_discr: 0x39554fea, your_discr: 0x2a99c705, required_min_rx: 300_000)
    assert_equal BIRD_DOWN, c.to_shex
  end

  def test_state_and_diag_as_numbers
    assert_equal BIRD_DOWN, Control.new(state: 1, diag: 3, poll: true, my_discr: 0x39554fea,
                                        your_discr: 0x2a99c705, required_min_rx: 300_000).to_shex
  end

  # The defaults: a Down packet at one a second (RFC 5880 6.8.3), Detect
  # Mult 3, version 1.
  def test_defaults
    assert_equal '20400318000000000000000000' + '0f4240000f424000000000', Control.new.to_shex
  end

  # Building is never validated: a packet can lie, so a receiver can be
  # watched handling it.

  def test_wrong_on_purpose
    c = Control.new(state: :up, version: 2, multipoint: true, length: 23, detect_mult: 0,
                    poll: true, final: true, desired_min_tx: 0, diag: 31)
    assert_equal '5ff1001700000000000000000000000000' + '0f424000000000', c.to_shex
    assert_equal 31, c.diag_name, 'a reserved diagnostic has no name'
  end

  def test_the_a_bit_without_a_section
    c = Control.new(state: :up, my_discr: 1, auth_present: true)
    assert c.auth_present?
    assert_equal 24, c.length
    assert_equal '20c4', c.to_shex[0, 4]
    assert_equal c, Control.new(c.encode)
  end

  def test_octets_after_the_packet_are_the_trailer
    c = Control.new(wire(BIRD_UP + 'ffff'))
    assert_equal "\xff\xff".b, c.trailer
    assert_equal 24, c.length, 'Length is as it came'
    assert_equal BIRD_UP, c.packet.unpack1('H*')
    assert_equal BIRD_UP + 'ffff', c.to_shex
  end

  # Only what cannot be represented is refused.

  def test_a_value_wider_than_its_field_is_refused
    assert_raise(ArgumentError) { Control.new(version: 8) }
    assert_raise(ArgumentError) { Control.new(diag: 32) }
    assert_raise(ArgumentError) { Control.new(state: 4) }
    assert_raise(ArgumentError) { Control.new(detect_mult: 256) }
    assert_raise(ArgumentError) { Control.new(length: 256) }
    assert_raise(ArgumentError) { Control.new(my_discr: 2**32) }
    assert_raise(ArgumentError) { Control.new(required_min_echo_rx: -1) }
  end

  def test_an_unknown_name_or_key_is_refused
    assert_raise(ArgumentError) { Control.new(state: :upp) }
    assert_raise(ArgumentError) { Control.new(diag: :tired) }
    assert_raise(ArgumentError) { Control.new(my_discriminator: 1) }
  end

  # Round trips: the hash, and another instance.

  def test_an_ordinary_packet_hashes_to_its_five_fields
    assert_equal({ state: :up, my_discr: 0x39554fea, your_discr: 0x2a99c705,
                   desired_min_tx: 300_000, required_min_rx: 300_000 }, Control.new(wire(BIRD_UP)).to_hash)
  end

  def test_an_unusual_field_adds_its_key
    h = Control.new(wire(BIRD_DOWN)).to_hash
    assert_equal :neighbor_signaled_session_down, h[:diag]
    assert_equal true, h[:poll]
    assert_equal 50_000, Control.new(wire(FRR_UP)).to_hash[:required_min_echo_rx]
  end

  def test_the_hash_round_trips_every_captured_packet
    FRR_BIRD.each do |pk|
      c = Control.new(pk.payload)
      assert_equal c.to_shex, Control.new(c.to_hash).to_shex
    end
  end

  def test_the_hash_round_trips_a_packet_that_lies
    c = Control.new(wire('5ff1001700000000000000000000000000' + '0f424000000000' + 'abcd'))
    assert_equal c.to_shex, Control.new(c.to_hash).to_shex
    assert_equal 23, c.to_hash[:length]
    c = Control.new(state: :up, auth_present: true)
    assert_equal c.to_shex, Control.new(c.to_hash).to_shex
  end

  def test_another_instance
    FRR_BIRD.each do |pk|
      c = Control.new(pk.payload)
      assert_equal c.to_shex, Control.new(c).to_shex
    end
  end

  def test_encode_is_binary
    assert_equal Encoding::BINARY, Control.new(state: :up).encode.encoding
  end

  def test_equal_packets
    assert_equal Control.new(wire(BIRD_UP)), Control.new(Control.new(wire(BIRD_UP)).to_hash)
    assert_not_equal Control.new(wire(BIRD_UP)), Control.new(wire(FRR_UP))
  end

  # tcpdump 4.99.6 printed these for test/fixtures/frr-bird.pcap, and for
  # packets built here, written to a pcap and read back with tcpdump -r,
  # on ospflab, 2026-11-20. to_s adds the discriminators.
  def test_to_s_is_tcpdumps_line
    assert_equal 'BFDv1, Control, State Up, Flags: [none], length: 24, my 0x39554fea, your 0x2a99c705',
                 Control.new(wire(BIRD_UP)).to_s
    assert_equal 'BFDv1, Control, State Down, Flags: [Poll], length: 24',
                 Control.new(wire(BIRD_DOWN)).to_s[/.*length: \d+/]
    assert_equal 'BFDv1, Control, State AdminDown, Flags: [none], length: 24',
                 Control.new(wire(FRR_ADMIN_DOWN)).to_s[/.*length: \d+/]
    {
      { poll: true, final: true } => 'Flags: [Poll, Final], length: 24',
      { cpi: true } => 'Flags: [Control Plane Independent], length: 24',
      { demand: true } => 'Flags: [Demand], length: 24',
      { multipoint: true } => 'Flags: [Multipoint], length: 24',
      { cpi: true, demand: true, multipoint: true } => 'Flags: [Control Plane Independent, Demand, Multipoint], length: 24',
      { length: 30 } => 'Flags: [none], length: 24',
      { trailer: "\xff\xff".b } => 'Flags: [none], length: 26'
    }.each do |fields, line|
      assert_equal "BFDv1, Control, State Up, #{line}", Control.new({ state: :up }.merge(fields)).to_s[/.*length: \d+/]
    end
  end
end
