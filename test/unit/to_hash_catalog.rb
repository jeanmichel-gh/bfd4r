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

# One to_hash per codec class, as bgp4r's test/unit/to_hash_catalog.rb:
# each must build its object and come back the same, from the hash and
# from the wire. to_hash_catalog_test.rb checks that every codec class
# has an entry.
module ToHashCatalog
  ENTRIES = [
    [BFD::Control, { state: :up, my_discr: 0x39554fea, your_discr: 0x2a99c705,
                     desired_min_tx: 300_000, required_min_rx: 300_000 }],
    [BFD::Control, { version: 2, diag: :neighbor_signaled_session_down, state: :init, detect_mult: 0,
                     my_discr: 0, your_discr: 1, desired_min_tx: 0, required_min_rx: 0,
                     required_min_echo_rx: 50_000, poll: true, final: true, cpi: true, demand: true,
                     multipoint: true, length: 99,
                     auth: { type: :simple_password, key_id: 7, password: 'secret' }, trailer: "\xff".b }],
    [BFD::Control, { diag: 31, state: :admin_down, my_discr: 1, your_discr: 0,
                     desired_min_tx: 1_000_000, required_min_rx: 1_000_000, auth_present: true }],
    [BFD::Auth::Password, { type: :simple_password, key_id: 7, password: 'secret', auth_len: 4 }],
    [BFD::Auth::Md5, { type: :keyed_md5, key_id: 7, sequence: 0x6d958397,
                       digest: ['2bb0e0f75e81b47a7541fa56c05071f7'].pack('H*') }],
    [BFD::Auth::Md5, { type: :meticulous_keyed_md5, key_id: 1, sequence: 2, digest: "\x01".b,
                       reserved: 0xff, auth_len: 24 }],
    [BFD::Auth::Sha1, { type: :meticulous_keyed_sha1, key_id: 7, sequence: 0x5b51c4c8,
                        digest: ['c58cd0ae70791046c89fcddc49ad2a9870edc3de'].pack('H*') }],
    [BFD::Auth::Sha1, { type: :keyed_sha1, key_id: 7, sequence: 0, digest: "\0".b * 20 }],
    [BFD::Auth::Unknown, { type: 9, data: "\xaa\xbb".b }],
    [BFD::Auth::Unknown, { type: :keyed_sha1, data: "\x07".b, auth_len: 28 }]
  ].freeze
end
