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

require 'bfd/validation'

module BFD
  # The catalog of crafted packets, as bgp4r's BGP::Fault and vtep4r's
  # VXLAN::Fault. The injector sends each one into a session and checks
  # what the receiver did against what the RFC expects.
  #
  # Each entry is built for a session that is Up: my_discr is the
  # sender's, your_discr the receiver's. All but the one wrong thing is
  # what a correct peer sends, so each entry has one Validation finding.
  module Fault
    # Each entry: [name, the Validation finding it makes, description,
    # what the RFC expects of the receiver, the RFC section, a block
    # (my_discr, your_discr) that builds the packet], then options:
    #
    #   ttl:   the TTL to send it with; 255 unless given
    #   auth:  :none for a receiver with no authentication in use, :sha1
    #          for one using Meticulous Keyed SHA1 with key 7, "secret"
    #
    # expect is :discard, or :record when the RFC does not say what a
    # receiver does: the fault matrix records what each one does.
    CATALOG = [
      [:truncated, :truncated, 'twenty octets, fewer than the Mandatory Section', :discard, '5880 4.1',
       ->(m, y) { Fault.up(m, y).encode.byteslice(0, 20) }],
      [:bad_version, :bad_version, 'version 2', :discard, '5880 6.8.6',
       ->(m, y) { Fault.up(m, y, version: 2) }],
      [:short, :short, 'Length 23', :discard, '5880 6.8.6',
       ->(m, y) { Fault.up(m, y, length: 23) }],
      [:short_auth, :short_auth, 'Length 24 with the A bit set', :discard, '5880 6.8.6',
       ->(m, y) { Fault.up(m, y, auth: Fault::SHA1_SECTION, length: 24).signed(Fault::KEY) }, { auth: :sha1 }],
      [:length_over_payload, :length_over_payload, 'Length 30, over the 24 octets sent', :discard, '5880 6.8.6',
       ->(m, y) { Fault.up(m, y, length: 30) }],
      [:detect_mult_zero, :detect_mult_zero, 'Detect Mult 0', :discard, '5880 6.8.6',
       ->(m, y) { Fault.up(m, y, detect_mult: 0) }],
      [:multipoint, :multipoint, 'the M bit set', :discard, '5880 6.8.6',
       ->(m, y) { Fault.up(m, y, multipoint: true) }],
      [:my_discr_zero, :my_discr_zero, 'My Discriminator 0', :discard, '5880 6.8.6',
       ->(_m, y) { Fault.up(0, y) }],
      [:your_discr_unknown, :your_discr_unknown, 'a Your Discriminator of no session', :discard, '5880 6.8.6',
       ->(m, y) { Fault.up(m, y ^ 0x8000_0000) }],
      [:your_discr_zero_up, :your_discr_zero_up, 'Your Discriminator 0 with State Up', :discard, '5880 6.8.6',
       ->(m, _y) { Fault.up(m, 0) }],
      [:auth_unexpected, :auth_unexpected, 'a Simple Password section to a session without authentication',
       :discard, '5880 6.8.6',
       ->(m, y) { Fault.up(m, y, auth: { type: :simple_password, key_id: 7, password: KEY }) }],
      [:auth_missing, :auth_missing, 'no Authentication Section to a session using it', :discard, '5880 6.8.6',
       ->(m, y) { Fault.up(m, y) }, { auth: :sha1 }],
      [:auth_failed, :auth_failed, 'a SHA1 digest made with the wrong key', :discard, '5880 6.7.4',
       ->(m, y) { Fault.up(m, y, auth: Fault::SHA1_SECTION).signed('wrong') }, { auth: :sha1 }],
      [:ttl_254, :ttl_not_255, 'sent with TTL 254', :discard, '5881 5',
       ->(m, y) { Fault.up(m, y) }, { ttl: 254 }],
      [:poll_and_final, :poll_and_final, 'both P and F set', :record, '5880 4.1, 6.5',
       ->(m, y) { Fault.up(m, y, poll: true, final: true) }],
      [:desired_min_tx_zero, :desired_min_tx_zero, 'Desired Min TX Interval 0', :record, '5880 4.1',
       ->(m, y) { Fault.up(m, y, desired_min_tx: 0) }]
    ].freeze

    # The key and section of the entries for a receiver using
    # authentication.
    KEY = 'secret'
    SHA1_SECTION = { type: :meticulous_keyed_sha1, key_id: 7, sequence: 1 }.freeze
    SHA1 = { type: :meticulous_keyed_sha1, keys: { 7 => KEY } }.freeze

    module_function

    # A correct Up packet from my_discr to your_discr, at 300 ms x 3,
    # with fields changed.
    def up(my_discr, your_discr, **fields)
      Control.new({ state: :up, my_discr: my_discr, your_discr: your_discr,
                    desired_min_tx: 300_000, required_min_rx: 300_000 }.merge(fields))
    end

    def names
      CATALOG.map(&:first)
    end

    # The entries, as Hashes.
    def catalog
      CATALOG.map do |name, finding, desc, expect, rfc, build, opts|
        opts ||= {}
        { name: name, finding: finding, description: desc, expect: expect, rfc: "RFC #{rfc}", build: build,
          ttl: opts.fetch(:ttl, 255), auth: opts.fetch(:auth, :none) }
      end
    end

    def entry(name)
      catalog.find { |e| e[:name] == name } or raise ArgumentError, "unknown fault #{name.inspect}, see Fault::CATALOG"
    end

    # The packet an entry names, from my_discr to your_discr: a Control,
    # or octets for a packet too short to be one.
    def build(name, my_discr:, your_discr:)
      entry(name)[:build].call(my_discr, your_discr)
    end

    # The same, as the UDP payload's octets.
    def wire(name, my_discr:, your_discr:)
      packet = build(name, my_discr: my_discr, your_discr: your_discr)
      packet.is_a?(String) ? packet : packet.encode
    end

    # What Validation is told about the receiver of an entry: the
    # session it is sent to, its authentication and the TTL.
    def context(name, your_discr:)
      e = entry(name)
      { known: [your_discr], auth: e[:auth] == :sha1 ? SHA1 : false, ttl: e[:ttl] }
    end
  end
end
