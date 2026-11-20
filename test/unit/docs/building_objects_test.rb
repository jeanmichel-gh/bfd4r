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

# docs/building-objects.md makes claims the code has to keep true: its
# examples and their results, and the list of codec classes. Both are
# checked against the library, as isis's test/docs does.
class BuildingObjectsDoc_Test < Test::Unit::TestCase
  DOC = File.read(File.expand_path('../../../docs/building-objects.md', __dir__))

  # The examples run in order, in one binding, so a later block uses an
  # earlier one's names. A line with "# =>" is checked.
  def test_every_example_gives_its_result
    scope = binding
    blocks = DOC.scan(/^```ruby\n(.*?)^```/m).flatten
    assert_operator blocks.size, :>=, 6
    checked = 0
    blocks.each do |block|
      statement = +''
      block.each_line do |line|
        code, want = line.split(/\s+# => /, 2)
        statement << code << "\n"
        next if want.nil? && !complete?(statement)

        got = scope.eval(statement)
        statement = +''
        next unless want

        assert_equal scope.eval(want), got, "#{code.strip} # => #{want.strip}"
        checked += 1
      end
    end
    assert_operator checked, :>=, 15
  end

  def test_the_classes_listed_are_the_codec_classes
    listed = DOC.scan(/^- `(BFD::[\w:]+)`$/).flatten.sort
    code = (['BFD::Control'] + ObjectSpace.each_object(Class)
                                          .select { |c| c < BFD::Auth::Section && c.subclasses.empty? }
                                          .map(&:name)).sort
    assert_equal code, listed
  end

  private

  # A statement is complete when Ruby can parse it alone.
  def complete?(source)
    RubyVM::InstructionSequence.compile(source)
    true
  rescue SyntaxError
    false
  end
end
