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
require 'bfd/validation'
require_relative '../support/pcap'

# One test per rule of RFC 5880 6.8.6 and RFC 5881 5, in their order,
# then the policies. The captures of test/fixtures have no finding.
class Validation_Test < Test::Unit::TestCase
  include BFD

  SHA1 = { type: :meticulous_keyed_sha1, keys: { 7 => 'secret' } }.freeze

  def up(**fields)
    Control.new({ state: :up, my_discr: 7, your_discr: 9 }.merge(fields))
  end

  def names(packet, **context)
    Validation.check(packet, **context).map(&:name)
  end

  # The real routers' packets, with the context they were sent in.

  def test_frr_and_bird_have_no_finding
    Pcap.bfd('test/fixtures/frr-bird.pcap').each do |pk|
      assert_equal [], names(pk.payload, auth: false, ttl: pk.ttl)
    end
  end

  def test_birds_authenticated_packets_have_no_finding
    {
      'auth-simple' => :simple_password, 'auth-keyed-md5' => :keyed_md5,
      'auth-meticulous-keyed-md5' => :meticulous_keyed_md5, 'auth-keyed-sha1' => :keyed_sha1,
      'auth-meticulous-keyed-sha1' => :meticulous_keyed_sha1
    }.each do |file, type|
      Pcap.bfd("test/fixtures/#{file}.pcap").each do |pk|
        assert_equal [], names(pk.payload, auth: { type: type, keys: { 7 => 'secret' } }, ttl: pk.ttl), file
      end
    end
  end

  def test_an_ordinary_packet_has_no_finding
    assert_equal [], names(up)
    assert_equal [], up.errors
  end

  # Before 6.8.6: fewer octets than the Mandatory Section.

  def test_truncated
    f = Validation.check(up.encode.byteslice(0, 23))
    assert_equal [:truncated], f.map(&:name)
    assert_equal :discard, f[0].action
  end

  # RFC 5880 6.8.6, in its order.

  def test_bad_version
    f = Validation.check(up(version: 0))
    assert_equal [:bad_version], f.map(&:name)
    assert_equal :discard, f[0].action
    assert_match(/RFC 5880 6\.8\.6/, f[0].reason)
    assert_equal [:bad_version], names(up(version: 2))
  end

  def test_short
    assert_equal [:short], names(up(length: 23))
    assert_equal [], names(up(length: 24))
  end

  def test_short_auth
    assert_equal [:short_auth], names(up(auth_present: true, length: 24))
    assert_equal [:short_auth], names(up(auth_present: true, length: 25), payload: 25)
    assert_equal [], names(up(auth: { type: :simple_password, password: 'a' }))
  end

  def test_length_over_payload
    assert_equal [:length_over_payload], names(up(length: 25))
    assert_equal [:length_over_payload], names(up, payload: 23)
    assert_equal [], names(up(trailer: "\0".b))
  end

  def test_the_payload_of_octets_is_their_size
    assert_equal [], names(up(length: 26, trailer: "\0\0".b).encode)
    assert_equal [:length_over_payload], names(up(length: 26, trailer: "\0".b).encode)
  end

  def test_detect_mult_zero
    assert_equal [:detect_mult_zero], names(up(detect_mult: 0))
  end

  def test_multipoint
    assert_equal [:multipoint], names(up(multipoint: true))
  end

  def test_my_discr_zero
    assert_equal [:my_discr_zero], names(up(my_discr: 0))
  end

  def test_your_discr_unknown_needs_the_sessions
    assert_equal [], names(up(your_discr: 5))
    assert_equal [:your_discr_unknown], names(up(your_discr: 5), known: [9])
    assert_equal [], names(up(your_discr: 9), known: [9])
  end

  def test_your_discr_zero_selects_no_session_by_it
    assert_equal [], names(Control.new(state: :down, my_discr: 7), known: [9])
  end

  def test_your_discr_zero_up
    assert_equal [:your_discr_zero_up], names(up(your_discr: 0))
    assert_equal [:your_discr_zero_up], names(up(your_discr: 0, state: :init))
    assert_equal [], names(up(your_discr: 0, state: :down))
    assert_equal [], names(up(your_discr: 0, state: :admin_down))
  end

  def test_auth_unexpected
    pw = up(auth: { type: :simple_password, key_id: 7, password: 'secret' })
    assert_equal [], names(pw), 'not checked unless auth: is given'
    assert_equal [:auth_unexpected], names(pw, auth: false)
    assert_equal [], names(up, auth: false)
  end

  def test_auth_missing
    assert_equal [:auth_missing], names(up, auth: SHA1)
  end

  def test_auth_failed
    sha1 = up(auth: { type: :meticulous_keyed_sha1, key_id: 7, sequence: 1 })
    assert_equal [], names(sha1.signed('secret'), auth: SHA1)
    {
      sha1 => /the digest does not match \(RFC 5880 6\.7\.4\)/,
      sha1.signed('wrong') => /the digest does not match/,
      up(auth: { type: :meticulous_keyed_sha1, key_id: 8 }).signed('secret') => /Auth Key ID 8 is not configured/,
      up(auth: { type: :meticulous_keyed_sha1, key_id: 7, auth_len: 27 }) => /Auth Len 27, not 28/,
      up(auth: { type: :keyed_sha1, key_id: 7 }).signed('secret') => /Auth Type keyed_sha1, and meticulous_keyed_sha1 is in use \(RFC 5880 6\.7\)/,
      up(auth_present: true, length: 26) => /no Authentication Section/,
      Control.new(up(auth: { type: :meticulous_keyed_sha1 }).encode.byteslice(0, 30)) => /too short/
    }.each do |packet, why|
      f = Validation.check(packet, auth: SHA1, payload: 255)
      assert_equal [:auth_failed], f.map(&:name), why.source
      assert_match why, f[0].reason
    end
  end

  def test_simple_password_failures
    keys = { type: :simple_password, keys: { 7 => 'secret' } }
    assert_equal [], names(up(auth: { type: :simple_password, key_id: 7, password: 'secret' }), auth: keys)
    {
      { key_id: 7, password: 'secreT' } => /password does not match \(RFC 5880 6\.7\.2\)/,
      { key_id: 6, password: 'secret' } => /Auth Key ID 6/,
      { key_id: 7, password: 'secret', auth_len: 10 } => /Auth Len 10/
    }.each do |section, why|
      f = Validation.check(up(auth: section.merge(type: :simple_password)), auth: keys, payload: 255)
      assert_match why, f.map(&:to_s).join
    end
  end

  # RFC 5881 5.

  def test_ttl_not_255
    f = Validation.check(up, ttl: 254)
    assert_equal [[:ttl_not_255, :discard]], f.map { [_1.name, _1.action] }
    assert_match(/RFC 5881 5/, f[0].reason)
    assert_equal [], names(up, ttl: 255)
  end

  def test_ttl_with_authentication_in_use_may_be_accepted
    f = Validation.check(up(auth: { type: :meticulous_keyed_sha1, key_id: 7 }).signed('secret'), ttl: 1, auth: SHA1)
    assert_equal [[:ttl_not_255, :report]], f.map { [_1.name, _1.action] }
  end

  # Reported, not discarded: the RFCs do not say what a receiver does.

  def test_poll_and_final
    f = Validation.check(up(poll: true, final: true))
    assert_equal [[:poll_and_final, :report]], f.map { [_1.name, _1.action] }
  end

  def test_desired_min_tx_zero
    f = Validation.check(up(desired_min_tx: 0))
    assert_equal [[:desired_min_tx_zero, :report]], f.map { [_1.name, _1.action] }
  end

  def test_findings_together_in_the_rfcs_order
    c = Control.new(state: :up, version: 2, length: 23, detect_mult: 0, multipoint: true,
                    poll: true, final: true, desired_min_tx: 0)
    assert_equal %i[bad_version short detect_mult_zero multipoint my_discr_zero your_discr_zero_up
                    ttl_not_255 poll_and_final desired_min_tx_zero], names(c, ttl: 64)
  end

  def test_every_rule_has_a_test_here
    tested = Validation_Test.instance_methods.grep(/\Atest_/).map(&:to_s)
    Validation::RULES.each_key { |name| assert(tested.any? { _1.include?(name.to_s) }, name.to_s) }
  end

  # The receive policies.

  def test_rfc_policy
    assert_equal :accept, Validation.decide(up)
    assert_equal :accept, Validation.decide(up(poll: true, final: true))
    assert_equal :discard, Validation.decide(up(detect_mult: 0))
    assert_equal :discard, Validation.decide(up, policy: :rfc, ttl: 254)
  end

  def test_lenient_policy_accepts_everything
    assert_equal :accept, Validation.decide(up(version: 0, detect_mult: 0), policy: :lenient)
    assert_equal :accept, Validation.decide("\0".b, policy: :lenient)
  end

  def test_strict_policy_raises_on_any_finding
    assert_equal :accept, Validation.decide(up, policy: :strict)
    e = assert_raise(Malformed_packet) { Validation.decide(up(poll: true, final: true), policy: :strict) }
    assert_equal :poll_and_final, e.finding.name
    assert_raise(Malformed_packet) { Validation.decide(up(my_discr: 0), policy: :strict) }
  end

  def test_an_unknown_policy_is_refused
    assert_raise(ArgumentError) { Validation.decide(up, policy: :loose) }
  end

  # Validation reads; it never changes the packet.
  def test_a_checked_packet_still_encodes_as_it_came
    c = up(version: 3, length: 99, trailer: "\xab".b)
    hex = c.to_shex
    Validation.check(c, auth: SHA1, ttl: 1, known: [])
    assert_equal hex, c.to_shex
  end
end
