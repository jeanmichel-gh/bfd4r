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

require 'bfd/control'

module BFD
  # Every receive rule, in one place, as bgp4r's and vtep4r's
  # validation.rb (routescope docs/design/protocol-conventions.md, part 2).
  #
  # It runs only on what was received. Building and encoding are never
  # checked. A finding says what the sender got wrong and what the RFC
  # has the receiver do about it; a receive policy turns the findings
  # into a verdict.
  #
  # The rules of RFC 5880 6.8.6 come in its order, then RFC 5881 5, then
  # two the RFCs do not have the receiver act on. Some rules need what
  # only a session knows. Each is checked only when the caller gives it:
  #
  #   payload:  the octets the encapsulating protocol carried; the
  #             packet's own size when not given
  #   known:    the discriminators of our sessions, anything with
  #             include?; for your_discr_unknown
  #   auth:     false when no authentication is in use (bfd.AuthType 0),
  #             or { type: :meticulous_keyed_sha1, keys: { 7 => 'secret' } }
  #   ttl:      the received TTL or Hop Limit
  #
  # The sequence number window of 6.7.3 and 6.7.4 needs bfd.RcvAuthSeq,
  # so the session checks it.
  module Validation
    # name     a Symbol, below
    # action   :discard, or :report for what the receiver may accept
    # reason   plain words, with the RFC section
    Finding = Struct.new(:name, :action, :reason) do
      def to_s
        "#{name}: #{reason} (#{action})"
      end
    end

    # Every finding, its action under :rfc, and its section.
    RULES = {
      truncated: [:discard, 'RFC 5880 4.1'],
      bad_version: [:discard, 'RFC 5880 6.8.6'],
      short: [:discard, 'RFC 5880 6.8.6'],
      short_auth: [:discard, 'RFC 5880 6.8.6'],
      length_over_payload: [:discard, 'RFC 5880 6.8.6'],
      detect_mult_zero: [:discard, 'RFC 5880 6.8.6'],
      multipoint: [:discard, 'RFC 5880 6.8.6'],
      my_discr_zero: [:discard, 'RFC 5880 6.8.6'],
      your_discr_unknown: [:discard, 'RFC 5880 6.8.6'],
      your_discr_zero_up: [:discard, 'RFC 5880 6.8.6'],
      auth_unexpected: [:discard, 'RFC 5880 6.8.6'],
      auth_missing: [:discard, 'RFC 5880 6.8.6'],
      auth_failed: [:discard, 'RFC 5880 6.7'],
      ttl_not_255: [:discard, 'RFC 5881 5'],
      poll_and_final: [:report, 'RFC 5880 4.1, 6.5'],
      desired_min_tx_zero: [:report, 'RFC 5880 4.1']
    }.freeze

    # The receive policies:
    #   :rfc      discard on a :discard finding, accept past a :report one
    #   :strict   raise Malformed_packet on any finding
    #   :lenient  accept everything, to watch what a sender sends
    POLICIES = %i[rfc strict lenient].freeze

    module_function

    # The findings for a packet: a Control, or the octets that came.
    def check(packet, payload: nil, known: nil, auth: nil, ttl: nil)
      if packet.is_a?(String)
        return [truncated(packet.bytesize)] if packet.bytesize < Control::SIZE

        payload ||= packet.bytesize
        packet = Control.new(packet)
      end
      payload ||= packet.encode.bytesize
      c = packet
      out = []
      add = ->(name, why, section = RULES.fetch(name)[1]) { out << finding(name, why, RULES.fetch(name)[0], section) }

      add.(:bad_version, "version #{c.version}, not #{Control::VERSION}") if c.version != Control::VERSION
      if c.auth_present?
        add.(:short_auth, "Length #{c.length} with the A bit set, under 26") if c.length < 26
      elsif c.length < Control::SIZE
        add.(:short, "Length #{c.length}, under #{Control::SIZE}")
      end
      add.(:length_over_payload, "Length #{c.length}, over the #{payload} octets carried") if c.length > payload
      add.(:detect_mult_zero, 'Detect Mult 0') if c.detect_mult.zero?
      add.(:multipoint, 'the M bit set') if c.multipoint?
      add.(:my_discr_zero, 'My Discriminator 0') if c.my_discr.zero?
      if known && !c.your_discr.zero? && !known.include?(c.your_discr)
        add.(:your_discr_unknown, format('Your Discriminator 0x%08x selects no session', c.your_discr))
      end
      if c.your_discr.zero? && %i[init up].include?(c.state_name)
        add.(:your_discr_zero_up, "Your Discriminator 0 with State #{c.state_name}")
      end
      check_auth(c, auth, add) unless auth.nil?
      check_ttl(ttl, auth, out) unless ttl.nil?
      add.(:poll_and_final, 'both P and F set; 4.1 and 6.5 forbid sending it') if c.poll? && c.final?
      add.(:desired_min_tx_zero, 'Desired Min TX Interval 0, which 4.1 reserves') if c.desired_min_tx.zero?
      out
    end

    # :accept or :discard for a received packet under a policy. The
    # keywords are check's.
    def decide(packet, policy: :rfc, **context)
      raise ArgumentError, "unknown receive policy #{policy.inspect}, one of #{POLICIES.join(', ')}" unless POLICIES.include?(policy)
      return :accept if policy == :lenient

      findings = check(packet, **context)
      raise Malformed_packet.new(findings.first, findings) if policy == :strict && !findings.empty?

      findings.any? { |f| f.action == :discard } ? :discard : :accept
    end

    def finding(name, why, action = RULES.fetch(name)[0], section = RULES.fetch(name)[1])
      Finding.new(name, action, "#{why} (#{section})")
    end

    # 6.8.6: the A bit against bfd.AuthType, then 6.7 for the type in use.
    def check_auth(c, auth, add)
      if auth == false
        add.(:auth_unexpected, 'the A bit set, and no authentication is in use') if c.auth_present?
        return
      end
      unless c.auth_present?
        add.(:auth_missing, "the A bit clear, and #{Auth.type_name(Auth.type_number(auth[:type]))} is in use")
        return
      end

      want = Auth.type_number(auth[:type])
      why = if c.auth.nil?
              'the A bit set, and no Authentication Section'
            elsif c.auth.auth_type != want
              "Auth Type #{c.auth.type_name}, and #{Auth.type_name(want)} is in use"
            elsif !c.auth.respond_to?(:failure)
              "an Authentication Section too short for #{c.auth.type_name}"
            else
              c.auth.failure(c, auth.fetch(:keys))
            end
      return unless why

      section = c.auth.respond_to?(:section) && c.auth.auth_type == want ? "RFC 5880 #{c.auth.section}" : 'RFC 5880 6.7'
      add.(:auth_failed, why, section)
    end

    # RFC 5881 5: without authentication, a TTL other than 255 MUST be
    # discarded; with it, it MAY be, so it is reported.
    def check_ttl(ttl, auth, out)
      return if ttl == 255

      in_use = auth.is_a?(Hash)
      out << finding(:ttl_not_255, "TTL #{ttl}#{in_use ? ', with authentication in use' : ''}",
                     in_use ? :report : :discard)
    end

    def truncated(size)
      finding(:truncated, "#{size} octets, fewer than the #{Control::SIZE} of the Mandatory Section")
    end
    private_class_method :finding, :check_auth, :check_ttl, :truncated
  end

  # Raised by the :strict receive policy. finding is the first finding,
  # findings all of them.
  class Malformed_packet < StandardError
    attr_reader :finding, :findings

    def initialize(finding, findings = [finding])
      @finding = finding
      @findings = findings
      super(finding.to_s)
    end
  end

  class Control
    # What the sender got wrong, as Validation::Finding, with no session
    # context.
    def errors
      Validation.check(self)
    end
  end
end
