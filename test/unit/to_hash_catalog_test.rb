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
require_relative 'to_hash_catalog'

class ToHashCatalog_Test < Test::Unit::TestCase
  include BFD

  # Every class that encodes a part of a packet.
  def codec_classes
    [Control] + ObjectSpace.each_object(Class).select { |c| c < Auth::Section && c.subclasses.empty? }
  end

  def build(klass, hash)
    klass == Control ? Control.new(hash) : Auth.new(hash)
  end

  def test_each_entry_round_trips_through_its_hash_and_its_octets
    ToHashCatalog::ENTRIES.each do |klass, hash|
      object = build(klass, hash)
      assert_instance_of klass, object, hash.inspect
      assert_equal hash, object.to_hash, klass.name
      assert_equal hash, build(klass, object.encode).to_hash, "#{klass.name} from the wire"
    end
  end

  def test_every_codec_class_has_an_entry
    assert_equal 5, codec_classes.size, 'discovery found the five classes'
    assert_equal codec_classes.map(&:name).sort, ToHashCatalog::ENTRIES.map { _1[0].name }.uniq.sort
  end
end
