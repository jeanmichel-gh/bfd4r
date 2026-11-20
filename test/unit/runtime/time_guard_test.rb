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

require "test/unit"
require "ripper"

# Protocol code never reads the system clock and never sleeps. It asks the
# injected clock for the time and the scheduler for a callback. CLAUDE.md,
# "Time and execution".
#
# This scans every file under bfd/ for the forbidden calls. It reads
# Ruby tokens, not text, so the words in a comment or a string do not
# count, and a real call cannot hide behind odd spacing.
#
# A file allowed to make one of these calls is listed in ALLOWED, with the
# reason. A new entry is justified in the pull request that adds it. An
# entry whose file no longer makes the call fails too, so the list cannot
# go stale.
class TimeGuard_Test < Test::Unit::TestCase
  LIB = File.expand_path("../../../bfd", __dir__)

  ALLOWED = {
    # The real clock: the one place that reads the system's, for protocol
    # time and for the wall time on log lines.
    "runtime/clock.rb" => "MonotonicClock#now and #wall"
  }.freeze

  FORBIDDEN = {
    "Time.now" => [:on_const, "Time", :on_ident, "now"],
    "Process.clock_gettime" => [:on_const, "Process", :on_ident, "clock_gettime"],
    "sleep" => [nil, nil, :on_ident, "sleep"]
  }.freeze

  # Names of forbidden calls found in Ruby +source+.
  def self.calls_in(source)
    tokens = Ripper.lex(source).map { |(_pos, type, text, _state)| [type, text] }
                   .reject { |type, _| %i[on_sp on_nl on_ignored_nl].include?(type) }
    found = []
    tokens.each_with_index do |(type, text), i|
      FORBIDDEN.each do |name, (recv_type, recv_text, call_type, call_text)|
        next unless type == call_type && text == call_text

        if recv_type.nil?
          prev = tokens[i - 1] if i.positive?
          # A bare call, not a method of that name on some other object.
          found << name unless prev && prev[0] == :on_period
        else
          period = tokens[i - 1] if i >= 1
          recv = tokens[i - 2] if i >= 2
          found << name if period&.first == :on_period && recv == [recv_type, recv_text]
        end
      end
    end
    found
  end

  def lib_files
    Dir.glob(File.join(LIB, "**", "*.rb")).sort
  end

  def relative(path)
    path.delete_prefix("#{LIB}/")
  end

  def test_the_scan_sees_the_whole_library
    assert_not_empty lib_files
    assert_include lib_files.map { |f| relative(f) }, "runtime/clock.rb"
  end

  def test_no_protocol_code_reads_the_system_clock_or_sleeps
    offenders = lib_files.reject { |f| ALLOWED.key?(relative(f)) }
                         .to_h { |f| [relative(f), self.class.calls_in(File.read(f))] }
                         .reject { |_, calls| calls.empty? }
    assert_equal({}, offenders, "direct time or sleep calls outside the allowed list")
  end

  def test_every_allowed_file_still_needs_its_exception
    ALLOWED.each_key do |rel|
      path = File.join(LIB, rel)
      assert File.exist?(path), "#{rel} is allowed but does not exist"
      assert_not_empty self.class.calls_in(File.read(path)), "#{rel} is allowed but makes no such call"
    end
  end

  # The scanner itself, so a broken scanner cannot pass the guard above by
  # finding nothing anywhere.
  def test_scanner_finds_each_forbidden_call
    assert_equal ["Time.now"], self.class.calls_in("t = Time.now\n")
    assert_equal ["Process.clock_gettime"],
                 self.class.calls_in("Process.clock_gettime(Process::CLOCK_MONOTONIC)\n")
    assert_equal ["sleep"], self.class.calls_in("sleep 1\n")
    assert_equal ["sleep"], self.class.calls_in("sleep(0.1)\n")
  end

  def test_scanner_ignores_comments_strings_and_other_receivers
    assert_equal [], self.class.calls_in("# never Time.now, never sleep\n")
    assert_equal [], self.class.calls_in("x = \"Time.now and sleep\"\n")
    assert_equal [], self.class.calls_in("@clock.now\nscheduler.sleep\n")
  end
end
