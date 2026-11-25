# bfdd4r and bfd4r-cli

`bfdd4r` is the BFD daemon that isis4rd, ospfd and bgp4rd ask for
sessions. `bfd4r-cli` is its client. The design is routescope's
`docs/design/bfd.md`, "The daemon". `test/unit/docs/daemon_test.rb`
holds the method list below to the code.

## One per network namespace

Every image of our routers starts `bfdd4r`. It binds the abstract socket
`@bfdd4r` (`\0bfdd4r`) first. A second `bfdd4r` in the same namespace
finds it in use, says so on standard error and exits with status 0, so
routers that share a namespace share one daemon.

```sh
bfdd4r                      # sessions come from the routers
bfdd4r -f bfdd4r.yml        # sessions from a file too, with the client "file"
bfdd4r -s @other --log -    # another socket; log to standard output
```

## The file

YAML. Unknown keys are refused by name. Intervals are in microseconds,
as in RFC 5880.

```yaml
socket: "@bfdd4r"
floor: 300000
sessions:
  - interface: eth1
    peer: 10.0.0.2
    local: 10.0.0.1
    desired_min_tx: 300000
    required_min_rx: 300000
    detect_mult: 3
```

The defaults are FRR's: 300 ms, 300 ms, 3. The floor is 300 ms: a
Desired Min TX or Required Min RX under it is refused, from the file or
a client. `floor` lowers it, for a bench or a router with cores to
spare; bfdd4r then logs a warning. `docs/timing.md` says why 300 ms.

## Sessions

- One hop, RFC 5881: UDP port 3784, a source port in 49152 to 65535 kept
  for the session, TTL or Hop Limit 255 sent and checked.
- Keyed by interface and peer. Every client that asks for the same key
  shares the session (RFC 5882 4.4). The last client to let go sends
  AdminDown for a Detection Time, then the session goes.
- IPv4 and IPv6, both tested against FRR's bfdd and BIRD
  (`test/interop/`).
- In a VRF too. A session is in the VRF its interface is in: the
  interface's master, when `ip -j -d link show` says it is a VRF. The
  client asks as for any other session. bfdd4r receives a VRF's
  packets on a socket bound to the VRF's device, one per VRF and local
  address, so two VRFs may hold the same address, as a PE's do
  (routescope `docs/design/bfd-vrf.md`). Rows and events give `vrf`, the
  VRF's name or `default`, as FRR names it. `test/interop/vrf_test.rb`
  runs two VRFs on one address, against bfdd4r and FRR's bfdd.

## The API

One JSON object per line on the socket, each way, as bgp4rd's, isisd's
and vtep4rd's:

```
-> {"id":1,"method":"session.add","params":{"interface":"eth1","peer":"10.0.0.2","local":"10.0.0.1","client":"isisd"}}
<- {"id":1,"result":{"interface":"eth1","peer":"10.0.0.2","state":"down",...}}
```

| Method | Params | Answers |
| --- | --- | --- |
| `api.info` | | version, methods, event kinds, event seq |
| `session.add` | interface, peer, local, client; desired_min_tx, required_min_rx, detect_mult | the session's row |
| `session.delete` | interface, peer, client | the clients left, and the state |
| `session.admin` | interface, peer, down (true or false) | the row |
| `session.set` | interface, peer; desired_min_tx, required_min_rx, detect_mult | the row |
| `show.sessions` | interface and peer, or none for all | rows |
| `show.counters` | | sessions, and packets that found no session, by why |
| `events.subscribe` | kinds, since | a stream, below |
| `events.unsubscribe` | | ends the stream |

A row has every RFC 5880 6.8.1 variable by its RFC name (`variables`),
its `vrf`, the negotiated transmit interval and Detection Time in microseconds,
whether a Poll Sequence runs, the clients, time in state, packets in and
out, flaps, and discards by finding name.

`last_down` is the last time the session went from Up to Down, a flap,
as its `session` event said it: the event's wall `time`, its `seq` and
the `diag`. It is `null` until the session has gone down once. A reader
that was not subscribed then, or comes after the event left the
backlog, still has it. AdminDown is not a Down here, as it is not a
flap. `in_state` counts on the monotonic clock; `time` is the wall
clock, as events are.

## Events

`events.subscribe` turns the connection into a stream of lines in
bgp4r's shape:

```
{"event":{"seq":3,"time":"2026-11-20T06:10:33.104Z","level":"warn","kind":"session","session":"eth1 10.0.0.2","message":"eth1 10.0.0.2 up -> down (neighbor_signaled_session_down)","data":{"from":"up","to":"down","diag":"neighbor_signaled_session_down","remote_state":"down","interface":"eth1","peer":"10.0.0.2","vrf":"default"}}}
{"keepalive":"2026-11-20T06:10:48.104Z","seq":3}
```

The kinds are `session` (a state change), `config` (a session added or
removed) and `overflow` (events lost).

A `session` event's `remote_state` is the state the peer's last packet
carried. RFC 5880 6.8.6 takes an Up session Down with diag
`neighbor_signaled_session_down` both when the peer says Down and when
it says AdminDown. RFC 5882 4.2 says a client acts on the first and not
on the second; `remote_state` tells them apart.

## A router's client: BFD::Client

isisd, ospfd and bgp4rd ask for sessions with `BFD::Client`
(`bfd/client.rb`; routescope's `docs/design/bfd-clients.md`):

```ruby
require 'bfd/client'

bfd = BFD::Client.new('isisd')         # $BFD4R_SOCKET, else @bfdd4r
bfd.want(interface: 'eth1', peer: '10.0.12.2', local: '10.0.12.1')
loop do
  IO.select(bfd.ios, nil, nil, 0.05)
  bfd.poll(clock.now).each do |e|
    # e.type: :state, :connected, :lost or :error
    # e.state: :down, :init, :up or :admin_down; e.failure? when Up went Down
  end
end
```

- It never blocks and keeps no thread. A router with one loop calls
  `poll` from it; one with threads, from one of them.
- `failure?` is true for an Up session that went Down, and not when
  either end is AdminDown: that is `:admin_down` (RFC 5882 4.2).
- When bfdd4r is not there, or goes, it says `:lost` once, tries again
  every second, and on connecting asks again for every wanted session.
  A session outlives its client's connection, so that is harmless.
- `close(release: true)` lets go of every wanted session.

## In a container: with-bfdd4r

```sh
with-bfdd4r isisd -c /etc/isis4r/isisd.yml -l -
```

starts bfdd4r in the background, then runs the command in its place,
with the same pid. bfdd4r is started again a second after it fails, and
not when it exits with 0: stopped, or another one already answers in
the namespace. It logs to `$BFDD4R_LOG`, `/var/log/bfdd4r.log` by
default. The router images use it as their entrypoint.

## bfd4r-cli

```sh
bfd4r-cli show.sessions --pretty
bfd4r-cli session.admin interface=eth1 peer=10.0.0.2 down=true
bfd4r-cli events.subscribe kinds=session
```

`-s NAME` picks another socket; `$BFD4R_SOCKET` does too.
