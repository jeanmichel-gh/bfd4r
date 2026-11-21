# The fault matrix

What each receiver does with each crafted packet of `BFD::Fault::CATALOG`,
against what the RFC expects. As vtep4r's `docs/fault-matrix.md`.

**Generated** by `test/interop/fault_matrix_test.rb` on 2026-11-21, Linux 7.0.0-43-generic,
bfd4r 0.1.0, Ruby 3.3.8, FRR 10.5.1, BIRD 2.18. Do not edit it by hand; run again, as root:

```sh
sudo BFD4R_MATRIX_DOC=docs/fault-matrix.md ruby -I. test/interop/fault_matrix_test.rb
```

bfd4r-sim brings a session Up with each receiver at 300 ms x 3, in the
network namespaces of `test/interop/lab.rb`. Then it goes silent and sends
only the case's packet, every 150 ms, for 2.4 s: longer than the 900 ms
Detection Time. Only a packet the receiver accepts restarts its detection
timer (RFC 5880 6.8.6). So:

- **kept Up**: the receiver accepted the packets.
- **went Down**: it discarded them, or accepted one that took the
  session Down. bfdd4r also names the findings whose counters rose.

The `detect_mult_zero` row cannot tell the two apart: a bfdd4r changed to
accept Detect Mult 0 went Down as well. For FRR and BIRD that row says
only that the session did not stay Up.

A cell in bold differs from what the RFC expects.

| Case | What | RFC expects | bfdd4r | FRR bfdd | BIRD |
| --- | --- | --- | --- | --- | --- |
| `valid` | a valid Up packet, the control | accept (5880 6.8.6) | kept Up | kept Up | kept Up |
| `nothing` | no packet, the other control | discard (5880 6.8.4) | went Down | went Down | went Down |
| `truncated` | twenty octets, fewer than the Mandatory Section | discard (5880 4.1) | went Down; discarded: truncated | went Down | went Down |
| `bad_version` | version 2 | discard (5880 6.8.6) | went Down; discarded: bad_version | went Down | went Down |
| `short` | Length 23 | discard (5880 6.8.6) | went Down; discarded: short | went Down | went Down |
| `short_auth` | Length 24 with the A bit set | discard (5880 6.8.6) | not run: needs authentication | not run: needs authentication | not run: needs authentication |
| `length_over_payload` | Length 30, over the 24 octets sent | discard (5880 6.8.6) | went Down; discarded: length_over_payload | went Down | went Down |
| `detect_mult_zero` | Detect Mult 0 | discard (5880 6.8.6) | went Down; discarded: detect_mult_zero | went Down | went Down |
| `multipoint` | the M bit set | discard (5880 6.8.6) | went Down; discarded: multipoint | went Down | went Down |
| `my_discr_zero` | My Discriminator 0 | discard (5880 6.8.6) | went Down; discarded: my_discr_zero | went Down | went Down |
| `your_discr_unknown` | a Your Discriminator of no session | discard (5880 6.8.6) | went Down; discarded: your_discr_unknown | went Down | went Down |
| `your_discr_zero_up` | Your Discriminator 0 with State Up | discard (5880 6.8.6) | went Down; discarded: your_discr_zero_up | went Down | went Down |
| `auth_unexpected` | a Simple Password section to a session without authentication | discard (5880 6.8.6) | went Down; discarded: auth_unexpected | went Down | went Down |
| `auth_missing` | no Authentication Section to a session using it | discard (5880 6.8.6) | not run: needs authentication | not run: needs authentication | not run: needs authentication |
| `auth_failed` | a SHA1 digest made with the wrong key | discard (5880 6.7.4) | not run: needs authentication | not run: needs authentication | not run: needs authentication |
| `ttl_254` | sent with TTL 254 | discard (5881 5) | went Down; discarded: ttl_not_255 | went Down | went Down |
| `poll_and_final` | both P and F set | record (5880 4.1, 6.5) | kept Up | kept Up | went Down |
| `desired_min_tx_zero` | Desired Min TX Interval 0 | record (5880 4.1) | kept Up | kept Up | kept Up |

"record" means the RFC does not say what a receiver does: the matrix
records it. The entries for a receiver using authentication are not run:
sessions have no authentication yet (routescope `docs/design/bfd.md`).

Every receiver does what the RFC expects in every case it was given.
