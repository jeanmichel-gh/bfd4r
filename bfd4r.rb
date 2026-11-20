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

# The entry point: requires the whole library.
require 'bfd/version'
require 'bfd/auth'
require 'bfd/control'
require 'bfd/validation'
require 'bfd/runtime/clock'
require 'bfd/runtime/scheduler'
require 'bfd/session'
require 'bfd/fault'
require 'bfd/behaviour'
require 'bfd/daemon/core'
require 'bfd/daemon/loopback'
