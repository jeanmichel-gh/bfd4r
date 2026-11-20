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

# test/fixtures/auth-*.pcap: two BIRD 2.0.12 on a Docker bridge on
# ospflab, 2026-11-20, one capture per authentication type, each with
# password "secret" as key 7. tcpdump 4.99.6 read them as below.
class Auth_Test < Test::Unit::TestCase
  include BFD

  KEY = 'secret'
  CAPTURES = {
    simple_password: 'auth-simple', keyed_md5: 'auth-keyed-md5',
    meticulous_keyed_md5: 'auth-meticulous-keyed-md5', keyed_sha1: 'auth-keyed-sha1',
    meticulous_keyed_sha1: 'auth-meticulous-keyed-sha1'
  }.transform_values { |name| Pcap.bfd("test/fixtures/#{name}.pcap") }

  # The first packet of the Meticulous Keyed SHA1 capture.
  SHA1_DOWN = '2044033429fbf2cf00000000000f4240000493e000000000' \
              '051c07005b51c4c8c58cd0ae70791046c89fcddc49ad2a9870edc3de'
  # The first packet of the Simple Password capture.
  PASSWORD_DOWN = '20440321c6743b8a00000000000f4240000493e000000000010907736563726574'

  def wire(hex)
    [hex].pack('H*')
  end

  def test_every_captured_packet_encodes_as_it_came
    CAPTURES.each do |type, packets|
      assert_operator packets.size, :>, 10, type
      packets.each do |pk|
        c = Control.new(pk.payload)
        assert_equal pk.payload.unpack1('H*'), c.to_shex, type
        assert_equal type, c.auth.type_name, type
        assert c.auth_present?
      end
    end
  end

  def test_the_hash_and_another_instance_round_trip
    CAPTURES.each_value do |packets|
      packets.each do |pk|
        c = Control.new(pk.payload)
        assert_equal c.to_shex, Control.new(c.to_hash).to_shex
        assert_equal c.to_shex, Control.new(c).to_shex
        assert_equal c.auth.to_shex, Auth.new(c.auth.to_hash).to_shex
        assert_equal c.auth.to_shex, Auth.new(c.auth).to_shex
      end
    end
  end

  # signed puts BIRD's digest back, for every packet of every keyed
  # capture: the digest is computed as RFC 5880 6.7.3 and 6.7.4 say.
  def test_signed_gives_birds_digest
    CAPTURES.each do |type, packets|
      next if type == :simple_password

      packets.each do |pk|
        c = Control.new(pk.payload)
        zeroed = Control.new(c.to_hash.merge(auth: c.auth.to_hash.merge(digest: "\0".b * c.auth.digest.bytesize)))
        assert_equal c.to_shex, zeroed.signed(KEY).to_shex, type
      end
    end
  end

  def test_parse_meticulous_keyed_sha1
    a = Control.new(wire(SHA1_DOWN)).auth
    assert_instance_of Auth::Sha1, a
    assert a.meticulous?
    assert_equal [5, 28, 7, 0, 0x5b51c4c8], [a.auth_type, a.auth_len, a.key_id, a.reserved, a.sequence]
    assert_equal 'c58cd0ae70791046c89fcddc49ad2a9870edc3de', a.digest.unpack1('H*')
    assert_equal 52, Control.new(wire(SHA1_DOWN)).length
  end

  def test_parse_simple_password
    a = Control.new(wire(PASSWORD_DOWN)).auth
    assert_instance_of Auth::Password, a
    assert_equal [1, 9, 7, 'secret'], [a.auth_type, a.auth_len, a.key_id, a.password]
  end

  def test_sections_from_fields
    assert_equal '010907736563726574', Auth::Password.new(key_id: 7, password: 'secret').to_shex
    assert_equal '0218070000000005' + '00' * 16, Auth::Md5.new(key_id: 7, sequence: 5).to_shex
    assert_equal '0318070000000005' + '00' * 16, Auth::Md5.new(key_id: 7, sequence: 5, meticulous: true).to_shex
    assert_equal '041c070000000005' + '00' * 20, Auth.new(type: :keyed_sha1, key_id: 7, sequence: 5).to_shex
    assert_equal '051c070000000005' + '00' * 20, Auth.new(type: 5, key_id: 7, sequence: 5).to_shex
  end

  def test_the_packet_counts_the_section_in_its_length
    c = Control.new(state: :down, my_discr: 0x29fbf2cf, required_min_rx: 300_000,
                    auth: { type: :meticulous_keyed_sha1, key_id: 7, sequence: 0x5b51c4c8 })
    assert_equal SHA1_DOWN, c.signed(KEY).to_shex
  end

  def test_birds_password_packet_from_fields
    c = Control.new(state: :down, my_discr: 0xc6743b8a, required_min_rx: 300_000,
                    auth: { type: :simple_password, key_id: 7, password: 'secret' })
    assert_equal PASSWORD_DOWN, c.to_shex
    assert_equal c, c.signed('anything'), 'a password has no digest to sign'
  end

  # Wrong on purpose.

  def test_a_wrong_digest_and_auth_len_go_out
    a = Auth::Sha1.new(key_id: 7, digest: "\x01\x02".b, auth_len: 99, reserved: 0xff)
    assert_equal '0463' + '07ff' + '00000000' + '0102', a.to_shex
    assert_equal a.to_shex, Auth.new(a.to_hash).to_shex
  end

  def test_a_password_of_any_length
    assert_equal '010307', Auth::Password.new(key_id: 7).to_shex
    long = 'x' * 40
    assert_equal 43, Auth::Password.new(password: long).auth_len
  end

  def test_an_unknown_type_is_kept
    c = Control.new(wire('20440320' + '00' * 20 + '0904aabb' + 'cc'))
    assert_instance_of Auth::Unknown, c.auth
    assert_equal [9, 4, "\xaa\xbb".b], [c.auth.auth_type, c.auth.auth_len, c.auth.data]
    assert_equal "\xcc".b, c.trailer
    assert_equal c.to_shex, Control.new(c.to_hash).to_shex
  end

  def test_a_keyed_section_too_short_for_its_fields_is_kept_whole
    c = Control.new(wire('2044031e' + '00' * 20 + '0406070000ff'))
    assert_instance_of Auth::Unknown, c.auth
    assert_equal 4, c.auth.auth_type
    assert_equal c.to_shex, Control.new(c.to_hash).to_shex
  end

  # The section is as long as its Auth Len, cut to what came: the rest
  # is the trailer.
  def test_auth_len_decides_where_the_section_ends
    c = Control.new(wire('2044031c' + '00' * 20 + '010407' + '61' + 'ffff'))
    assert_equal ['a', "\xff\xff".b], [c.auth.password, c.trailer]
    c = Control.new(wire('2044031c' + '00' * 20 + '01ff0761'))
    assert_equal ['a', 255, ''.b], [c.auth.password, c.auth.auth_len, c.trailer]
    assert_equal '01ff0761', c.auth.to_shex
  end

  def test_an_a_bit_with_one_octet_after_is_a_trailer
    c = Control.new(wire('20440318' + '00' * 20 + '01'))
    assert_nil c.auth
    assert_equal "\x01".b, c.trailer
  end

  def test_a_key_too_long_for_the_field_is_refused
    c = Control.new(state: :up, auth: { type: :keyed_md5 })
    assert_raise(ArgumentError) { c.signed('x' * 17) }
    assert_nothing_raised { c.signed('x' * 16) }
  end

  def test_an_unknown_type_name_or_key_is_refused
    assert_raise(ArgumentError) { Auth.new(type: :keyed_sha256) }
    assert_raise(ArgumentError) { Auth.new(key_id: 1) }
    assert_raise(ArgumentError) { Auth::Sha1.new(key: 'x') }
    assert_raise(ArgumentError) { Auth::Sha1.new(sequence: 2**32) }
  end

  # tcpdump 4.99.6 -v printed each section on three lines; to_s joins them.
  def test_to_s_is_tcpdumps
    assert_equal 'Authentication: Meticulous Keyed SHA1 (5), length: 28, Auth Key ID: 7, ' \
                 'Sequence Number: 0x5b51c4c8, Hash: c58cd0ae70791046c89fcddc49ad2a9870edc3de',
                 Control.new(wire(SHA1_DOWN)).auth.to_s
    assert_equal 'Authentication: Simple Password (1), length: 9, Auth Key ID: 7, Password: secret',
                 Control.new(wire(PASSWORD_DOWN)).auth.to_s
    md5 = Control.new(CAPTURES[:keyed_md5].first.payload).auth.to_s
    assert_match(/\AAuthentication: Keyed MD5 \(2\), length: 24, Auth Key ID: 7, Sequence Number: 0x\h{8}, Digest: \h{32}\z/, md5)
  end
end
