# CLAUDE.md

A guide for AI agents working on bfd4r. Read it before changing
anything.

## What this is

bfd4r is a pure Ruby library to build, parse and check BFD (RFC 5880,
5881), for routing labs and protocol tests, in the same way bgp4r
scripts BGP peers. Its runtime needs only Ruby and its default gems.

Programs will be built on the library:

| Program | What it is |
| --- | --- |
| `bfdd4r` | the BFD daemon that isis4rd, ospfd and bgp4rd ask for sessions, one per network namespace |
| `bfd4r-sim` | an injector and fault source, over HTTP |
| `bfd4r-cli` | `bfdd4r`'s client, over its socket |

It is one of the owner's routing repositories, with bgp4r, ospfv2, isis,
vtep4r and datalink-socket. routescope, the web console for their labs,
will read `bfdd4r`.

The design is routescope's `docs/design/bfd.md`, approved 2026-11-20.
It is built to routescope's `docs/design/protocol-conventions.md`, the
one way to build a protocol across the repositories, approved the same
day. When this file does not say, do what those say, then what bgp4r
and vtep4r do.

## Layout

```
bfd4r.rb            the entry point: requires the whole library
bfd/control.rb      BFD::Control, the packet of RFC 5880 4.1
bfd/auth.rb         BFD::Auth: the registry of Authentication Sections
bfd/auth/           Password (4.2), Md5 and Sha1 (4.3, 4.4), Unknown
bfd/validation.rb   BFD::Validation: the receive rules of RFC 5880 6.8.6
                    and RFC 5881 5, and the receive policies
bfd/session.rb      BFD::Session: the state machine and timers of RFC 5880
                    6.8, told the time, answering with actions
bfd/runtime/        the clock and the scheduler, copied from isis; loop.rb,
                    one thread that owns a scheduler, for bfd4r-sim
bfd/fault.rb        BFD::Fault: the catalog of crafted packets, one per
                    Validation finding
bfd/behaviour.rb    BFD::Behaviour: a peer that misbehaves over time, on
                    one of eight scripts
bfd/daemon/core.rb  Daemon::Core: bfdd4r's sessions, shared by clients,
                    demultiplexed, counted, on one scheduler; no sockets
bfd/daemon/events.rb  the event stream, in bgp4r's shape, from vtep4r
bfd/daemon/loopback.rb  an in-memory network for daemons on one scheduler
bfd/daemon/runner.rb  bfdd4r's one thread: the Core, its scheduler, a queue
bfd/daemon/udp.rb   RFC 5881 over UDP: port 3784, TTL 255 sent and read back
bfd/daemon/api.rb, client.rb, cli.rb, server.rb, config.rb
                    the JSON-lines API on @bfdd4r, its client, bfd4r-cli,
                    the bfdd4r program and its file (docs/daemon.md)
bfd/sim/            bfd4r-sim: the injector, its HTTP API, its file and
                    the program (docs/sim.md)
bfd/logging.rb      log lines to a callable, without Ruby's Logger
exe/                bfdd4r, bfd4r-cli, bfd4r-sim
test/unit/          the unit tier: one test file per source file
test/unit/docs/     tests that hold docs/ to the code
test/interop/       the interop tier: bfdd4r against FRR's bfdd and BIRD in
                    network namespaces, root (lab.rb, interop_test.rb);
                    bench.rb, the timing bench (docs/timing.md);
                    fault_matrix_test.rb, the fault matrix
                    (docs/fault-matrix.md)
test/functional/    the functional tier: our session against each
                    behaviour, and each fault; two daemon cores and the
                    injector over the loopback; all on a manual clock
test/support/       pcap.rb, which reads the fixtures; pair.rb, two
                    sessions joined on a manual clock
test/fixtures/      captures of FRR's bfdd and BIRD, below
docs/               building-objects.md, daemon.md, sim.md, timing.md
```

## Conventions

- **Building and encoding are never validated, and that is a feature.**
  This library is for negative testing. It must put on the wire any
  version, flag, length, discriminator, interval or authentication
  section, so a real BFD can be watched handling them. Never add a
  check to a constructor, to `encode` or to `to_hash` that refuses
  something merely invalid.
  - Validation lives in one place, `bfd/validation.rb`, and runs only
    on what was received. Each finding has its name, its action and
    its RFC section. It raises only under the `:strict` policy.
  - A constructor may refuse only what it cannot represent at all, such
    as a Detect Mult above 255, since the alternative is silently
    sending another value.
- **Keep what you cannot read, and write it back.** A packet read from
  the wire keeps its Length and A bit as they came, an Authentication
  Section it cannot read as `Auth::Unknown`, and any octets after the
  section as its trailer. `encode` gives back what arrived, byte for
  byte.
- **Every class is built four ways:** from field values, a hash, its
  wire bytes or another instance. `encode` returns wire bytes,
  `to_hash` a hash that round trips through `new`, `to_s` tcpdump's
  form. `docs/building-objects.md` is the guide, and a test runs it.
  - **A String is always wire bytes.** A field that is a String (a
    password, a digest, the trailer) goes in a hash.
  - **A constructor does not consume its String.** It reads with
    `byteslice`, never `slice!`.
- **Every codec class has an entry in `test/unit/to_hash_catalog.rb`.**
  A test finds the classes in the code and fails on one without.
- **Tests check round trips** against real captures where there is one.
  One test file per source file, with the same name and `_test.rb`.
- **Every Validation rule has a test named for it.** A test fails on a
  rule without one.
- **Runtime gems: none.** `digest`, `json`, `socket` and `yaml` ship
  with Ruby. Ruby 4.0 made `logger` a bundled gem, so `bfd/logging.rb`
  writes its own lines. A gem needs a reason in the pull request.
- **One thread owns the sessions.** Socket readers and the API only push
  work on the Runner's queue, or run a block on its loop with
  `on_loop`, as vtep4rd's worker.
- Do not redefine methods of standard library classes.
- Do not mutate string literals. CI runs with
  `--enable-frozen-string-literal`. An octet buffer is `String.new`,
  which is binary, never `+''`.
- Two space indent.
- A new Ruby file starts with the GPL header of `bfd/control.rb`, with
  "This file is part of BFD4R". The license for now is GPL 3 or later,
  until the owner reviews the licenses of all the repositories
  together.

## Time and execution

As isis (routescope `docs/design/protocol-conventions.md`, part 8):

- **Protocol code never reads the system clock and never sleeps.**
  `BFD::Session` is told the time with each call and answers with
  actions; it keeps no thread, socket or clock. bfdd4r will run every
  session on one thread with a `Runtime::Scheduler`, calling `tick` at
  each session's `next_due`.
- Time is seconds as a Float, on a monotonic clock. Intervals are
  microseconds, as on the wire.
- Randomness is injected too: a session takes a `Random`, for its
  discriminator and its jitter, so a test with a seed runs the same
  every time.
- `test/unit/runtime/time_guard_test.rb` scans `bfd/` for `Time.now`,
  `Process.clock_gettime` and `sleep`. Only `bfd/runtime/clock.rb` may
  read the system clock.

## The fixtures

Captured on ospflab, 2026-11-20, with tcpdump 4.99.6 on a Docker bridge:

| File | What |
| --- | --- |
| `frr-bird.pcap` | FRR 10.2.1's bfdd and BIRD 2.0.12, 300 ms x 3; FRR's peer shut down and brought back, so every state, a Poll and a Final |
| `auth-*.pcap` | two BIRD 2.0.12, one file per authentication type, password "secret" as key 7 |

## Other daemons are for interop

FRR's bfdd and BIRD are what bfd4r is tested against, in the fault
matrix and in routescope's labs. They do not replace it.

## Running tests

```sh
bundle exec ruby test/run_unit.rb
bundle exec ruby --enable-frozen-string-literal test/run_unit.rb
bundle exec ruby test/run_functional.rb
sudo ruby -I. test/interop/interop_test.rb     # root, FRR and BIRD 2
sudo ruby -I. test/interop/fault_matrix_test.rb
```

The fault matrix sends every fault, by `bfd4r-sim`, to `bfdd4r`, FRR's
bfdd and BIRD in network namespaces, and holds `bfdd4r` to the RFC.
With `BFD4R_MATRIX_DOC=docs/fault-matrix.md` it writes the document,
which a unit test holds to the catalog. A new fault goes in with the
matrix run again.

The functional tier runs our session against each `Behaviour` and
sends it each `Fault`, and runs two daemon cores over the loopback, on
a manual clock, in one process. It also runs two `bfdd4r` over real
UDP on 127.0.0.1 and 127.0.0.2, in real time and without root, and
drives them through their sockets. `bfd4r-sim`'s injector runs there
too, against two daemon cores on the manual clock: every behaviour,
every fault. And `bfd4r-sim` with `bfdd4r` as programs over real UDP,
driven over HTTP.

The interop tier runs bfdd4r against FRR's bfdd and BIRD 2, installed
natively, in two network namespaces, over IPv4 and IPv6, as ospfv2's
and isis's interop tiers run FRR. It needs root. A case omits without
FRR or BIRD unless `BFD4R_REQUIRE_FRR` or `BFD4R_REQUIRE_BIRD` is set;
CI sets both. Ubuntu 26.04 enforces an AppArmor profile for bfdd that
denies its pid file under the lab's pathspace; `Lab.missing` says how to
unload it. The lab tier comes with the steps that need it
(`docs/design/bfd.md` in routescope, "Tests").

- **Every Fault entry makes exactly one Validation finding**, and every
  finding has an entry. A test checks both.
- **Every Behaviour script has a functional test named for it.**

## Rules for agents

- Work on a branch named `claude/<short-topic>`. Never push to master.
- Do not stack a pull request on another one's branch.
- One topic per pull request. Small diffs.
- Run the full unit suite before opening a pull request. All tests
  must pass.
- New behaviour needs a test. A fix needs a test that failed before it.
  **Check that the proof proved something:** break the code on
  purpose and see the test fail. Commit before you break it.
- Larger work starts with a design in routescope's `docs/design/`,
  approved by the owner before any code.
- Update a branch by rebasing on `origin/master` and pushing with
  `--force-with-lease`. Do not merge master into it.
- Cite the RFC section in a comment when you write wire format logic.
  Open the RFC and check the section against its text. Never cite from
  memory. The RFCs are in routescope's `specs/rfc/`.
- Measure rather than recall: what a router sends, what tcpdump prints.
- Work out what the code was built to do before concluding it is
  wrong. Say "I do not know why this is like this" until you know.
- Do not delete or weaken a test to make a change pass.
- If you find a bug you are not fixing, list it in the pull request.
- Keep this file true in the pull request that makes it false.
- Write in plain, short sentences: code comments, documents, pull
  requests.

## Where the work is going

The steps are in routescope's `docs/design/bfd.md`, "Work".

| Step | Status |
| --- | --- |
| 1. `Control`, the authentication sections, `Validation` | Done, #1 |
| 2. `Session` on a manual clock | Done, #2 |
| 3. `Fault` and `Behaviour`, the functional tier | Done, #3 |
| 4a. The daemon core: shared sessions, demultiplexing, counters, events | Done, #4 |
| 4b. UDP, the API, the file, `bfdd4r` and `bfd4r-cli`, one per namespace | Done, #5 |
| 4c. Interop with FRR and BIRD, IPv6, the timing bench | Done, #6 |
| 5a. `bfd4r-sim`: the injector, its HTTP API, the functional tier | Done, #7 |
| 5b. The fault matrix against `bfdd4r`, FRR's bfdd and BIRD | This pull request |
| 6. The clients in isis, ospfv2 and bgp4r | Not started |
| 7. routescope's views | Not started |
| 8. bfd-lab and l3vpn-lab's netem case | Not started |

Authentication in sessions, multihop, Echo and asking for Demand mode
come after the first version. A session honours Demand mode from the
remote end. The sequence number window of RFC 5880 6.7.3 and 6.7.4
needs `bfd.RcvAuthSeq`, so it will be `Session`'s, with
authentication.
