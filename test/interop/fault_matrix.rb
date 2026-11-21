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

# What the fault matrix measured, as words, and the document it writes:
# docs/fault-matrix.md, as vtep4r's. Used by
# test/interop/fault_matrix_test.rb.
module FaultMatrix
  module_function

  # Why "kept Up" means accepted: the sender goes silent and sends only
  # the case's packet, every 150 ms, for longer than the 900 ms
  # Detection Time. Only a packet the receiver accepted restarts its
  # detection timer (RFC 5880 6.8.6, 6.8.4). This works the same on
  # every receiver; FRR and BIRD count no discards by reason.
  def outcome(state)
    state == 'up' ? 'kept Up' : "went #{state.to_s.capitalize}"
  end

  # bfdd4r also says why: the findings whose counters rose.
  def ours(state, before, after)
    rose = after.select { |k, v| v.to_i > before[k].to_i }.keys
    rose.empty? ? outcome(state) : "#{outcome(state)}; discarded: #{rose.join(', ')}"
  end

  def accepted?(outcome)
    outcome.start_with?('kept Up')
  end

  # Does +outcome+ do what the RFC expects? nil when the RFC says nothing.
  def agrees?(expect, outcome)
    case expect
    when :discard then !accepted?(outcome)
    when :accept then accepted?(outcome)
    end
  end

  def cell(expect, outcome)
    return outcome if outcome.nil? || outcome.start_with?('not run')

    agrees?(expect, outcome) == false ? "**#{outcome}**" : outcome
  end

  RECEIVERS = { bfdd4r: 'bfdd4r', frr: 'FRR bfdd', bird: 'BIRD' }.freeze

  def render(rows, versions:, date:, kernel:)
    lines = []
    lines << '# The fault matrix'
    lines << ''
    lines << 'What each receiver does with each crafted packet of `BFD::Fault::CATALOG`,'
    lines << "against what the RFC expects. As vtep4r's `docs/fault-matrix.md`."
    lines << ''
    lines << "**Generated** by `test/interop/fault_matrix_test.rb` on #{date}, Linux #{kernel},"
    lines << "#{versions}. Do not edit it by hand; run again, as root:"
    lines << ''
    lines << '```sh'
    lines << 'sudo BFD4R_MATRIX_DOC=docs/fault-matrix.md ruby -I. test/interop/fault_matrix_test.rb'
    lines << '```'
    lines << ''
    lines << 'bfd4r-sim brings a session Up with each receiver at 300 ms x 3, in the'
    lines << 'network namespaces of `test/interop/lab.rb`. Then it goes silent and sends'
    lines << "only the case's packet, every 150 ms, for 2.4 s: longer than the 900 ms"
    lines << 'Detection Time. Only a packet the receiver accepts restarts its detection'
    lines << 'timer (RFC 5880 6.8.6). So:'
    lines << ''
    lines << '- **kept Up**: the receiver accepted the packets.'
    lines << '- **went Down**: it discarded them, or accepted one that took the'
    lines << '  session Down. bfdd4r also names the findings whose counters rose.'
    lines << ''
    lines << 'The `detect_mult_zero` row cannot tell the two apart: a bfdd4r changed to'
    lines << 'accept Detect Mult 0 went Down as well. For FRR and BIRD that row says'
    lines << 'only that the session did not stay Up.'
    lines << ''
    lines << 'A cell in bold differs from what the RFC expects.'
    lines << ''
    lines << "| Case | What | RFC expects | #{RECEIVERS.values.join(' | ')} |"
    lines << "| --- | --- | --- |#{' --- |' * RECEIVERS.size}"
    rows.each do |r|
      cells = RECEIVERS.keys.map { |k| cell(r[:expect], r[k]) }
      lines << "| `#{r[:name]}` | #{r[:description]} | #{r[:expect]} (#{r[:rfc]}) | #{cells.join(' | ')} |"
    end
    lines << ''
    lines << '"record" means the RFC does not say what a receiver does: the matrix'
    lines << 'records it. The entries for a receiver using authentication are not run:'
    lines << 'sessions have no authentication yet (routescope `docs/design/bfd.md`).'
    lines << ''
    differ = rows.flat_map do |r|
      RECEIVERS.filter_map { |k, label| "#{label} on `#{r[:name]}`" if r[k] && agrees?(r[:expect], r[k]) == false }
    end
    lines << if differ.empty?
               'Every receiver does what the RFC expects in every case it was given.'
             else
               "Differs from the RFC: #{differ.join(', ')}. Why is not known here."
             end
    "#{lines.join("\n")}\n"
  end
end
