# bfd4r

BFD in Ruby (RFC 5880, 5881): a library to build, parse and check BFD
Control packets, a fault catalog, the daemon `bfdd4r` that isis4rd,
ospfd and bgp4rd ask for sessions, and the injector `bfd4r-sim`, for
routing labs and protocol tests.

The design is routescope's `docs/design/bfd.md`, approved 2026-11-20.
It is built to routescope's `docs/design/protocol-conventions.md`.
