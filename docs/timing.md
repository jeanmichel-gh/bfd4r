# Timing

What bfdd4r holds, measured. routescope's `docs/design/bfd.md` set the
floor at 50 ms x 3 "until step 4 measures what holds for an hour with
the routers busy". This is that measurement, and the floor it chose:
300 ms.

## The bench

`test/interop/bench.rb`, as root:

- bfdd4r against FRR's bfdd, one IPv4 session, in two network
  namespaces on a veth pair (`test/interop/lab.rb`).
- Both ends at the same interval, Detect Mult 3.
- "Busy" is one Ruby process per core spinning in a loop, so every core
  is taken: harder than a router at work, on purpose.
- Flaps are counted on both sides: bfdd4r's `flaps`, and FRR's
  `session-down`.
- The bench writes `floor` in bfdd4r's file, so it can measure under
  the floor.
- The gaps between the packets bfdd4r sent are measured from a capture
  in FRR's namespace.

```sh
sudo ruby test/interop/bench.rb --interval 50 --minutes 60
sudo ruby test/interop/bench.rb --interval 300 --minutes 3 --busy 0
```

## Results

ospflab, 2026-11-20: 6 cores (aarch64), Ruby 3.3.8, FRR 10.5.1.
Gaps in milliseconds.

| Interval | Busy | Minutes | Flaps (ours, FRR's) | p50 | p99 | p99.9 | Max | Detection Time |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 50 | 0 of 6 | 3 | 0, 0 | | 50.8 | 59.0 | 79.9 | 150 |
| 50 | 6 of 6 | 3 | 0, 0 | | 55.1 | 77.3 | 125.2 | 150 |
| 50 | 6 of 6 | 1 | 1, 1 | 44.4 | 62.5 | 116.3 | 197.9 | 150 |
| 50 | 6 of 6 | 60 | 5, 5 | 44.0 | 51.0 | 59.1 | 2525.6 | 150 |
| 100 | 6 of 6 | 3 | 0, 0 | | 102.0 | 120.8 | 146.9 | 300 |
| 100 | 6 of 6 | 60 | 5, 5 | 88.0 | 101.0 | 121.6 | 902.5 | 300 |
| 200 | 6 of 6 | 60 | 4, 4 | 175.0 | 200.0 | 229.2 | (a clock step) | 600 |
| 300 | 6 of 6 | 3 | 0, 0 | | 301.1 | 333.3 | 333.3 | 900 |
| 300 | 6 of 6 | 60 | 0, 0 | 263.0 | 300.0 | 316.4 | 383.1 | 900 |

In the 60-minute run at 50 ms, FRR received 81,932 of the 81,936
packets bfdd4r sent: nothing was lost on the link. Every flap was a
packet sent late, with every core busy. The 2.5 s maximum is the gap
while the session was Down after a flap, at one packet a second (RFC
5880 6.8.3), not a late packet.

At 100 ms the hour also had 5 flaps, though only 3 of bfdd4r's gaps
reached the 300 ms Detection Time. FRR runs on the same busy cores, so
some flaps are likely FRR sending late, which bfdd4r detects. The bench
counts flaps, not which side caused each.

The 200 ms hour had 4 flaps on both sides. In it ntpd stepped
ospflab's clock by 666 s: the VM had been paused. The capture's
timestamps are wall time, so its largest gap (666 s) is that step, not
BFD. One flap may come from the pause. The other three are busy cores,
as at 50 and 100 ms. No clock step fell in the 50, 100 or 300 ms hours.

Gaps above the interval (3,386 of 81,918 at 50 ms) are the scheduler
waking the loop late; RFC 5880 6.8.7 forbids sending faster than the
interval, not slower.

## The floor

The floor is the least Desired Min TX and Required Min RX bfdd4r takes
from a client or its file. It is not the default, which is FRR's 300 ms
x 3. It stops a client from asking for
an interval that flaps the session when the router is busy.

It is 300 ms (`Core::FLOOR`). Of the hours with every core busy, only
300 ms had no flap; 50, 100 and 200 ms had 4 or 5. At 300 ms the
largest gap, 383 ms, was well under the 900 ms Detection Time.

The floor equals the default, so a client cannot ask for anything
faster than FRR's default. `floor` in bfdd4r's file lowers it, for a
bench or a router with cores to spare; bfdd4r logs a warning when it
does. The busy cores here are harder than a router at work, so a lower
floor may hold in a lab that is not loaded; this bench does not say.
