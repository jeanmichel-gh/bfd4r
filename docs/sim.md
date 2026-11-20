# bfd4r-sim

`bfd4r-sim` sends BFD that a test chooses: one crafted packet, a fault
from the catalog, or a session to a peer that misbehaves on a script.
The design is routescope's `docs/design/bfd.md`, "The injector".
`test/unit/docs/sim_test.rb` holds the paths and event kinds below to
the code.

```sh
bfd4r-sim -f sim.yml                  # the API on 127.0.0.1:8080
bfd4r-sim -f sim.yml --api 9000 -d    # another port; log at debug
```

## The file

YAML. Unknown keys are refused by name, and so are bfdd4r's: the sim's
session comes from `POST /api/peer`, not a file.

```yaml
local: 10.0.12.1      # the address it sends from, required
interface: eth1       # the interface it sends on, optional
api: 127.0.0.1:8080   # its HTTP API, the loopback by default
```

## Port 3784

It sends from a source port in 49152 to 65535 and binds nothing else.
It binds port 3784 on `local` only for a peer session, so it can share
a namespace with a `bfdd4r` that uses other addresses. When a `bfdd4r`
holds the port on that address, `POST /api/peer` answers 409.

## The HTTP API

As `bgp4r-sim` and `vtep4r-sim`: GET for reads, POST for actions, JSON
bodies. A POST carries `X-BFD4R: routescope`; without it, 403. A
request the caller can fix answers 400, a state that refuses it now
409, both with `{"error": "..."}`. `GET /api` lists the paths.

| Path | Does |
| --- | --- |
| `POST /api/send` | one Control packet: any field, `ttl`, `source_port`, or raw `octets` in hex |
| `POST /api/fault` | one catalog entry (`case`); answers its finding, what the RFC expects and the section |
| `POST /api/peer` | a well behaved session to `to`, with its timers; with `behaviour`, on that script from its first packet |
| `POST /api/behave` | switch the running session to a script (`name`, `after`) |
| `POST /api/stop` | end the script and the session; with `script: true`, the script only |
| `GET /api/status` | the version, the address, and the peer session's state and 6.8.1 variables |
| `GET /api/sent` | packets sent: by `send`, by fault, and by the session |
| `GET /api/received` | packets received, from the peer, the discards by finding, the last 100 |
| `GET /api/catalog` | the actions, the fault catalog and the behaviours |
| `GET /api/events` | the events after `since=N` |

A send or fault to the peer of the running session takes its My and
Your Discriminator from that session unless the body gives them. A
fault is built for a receiver whose session is Up.

```sh
H='X-BFD4R: routescope'
curl -s -H "$H" -d '{"to":"10.0.12.2"}' 127.0.0.1:8080/api/peer
curl -s -H "$H" -d '{"case":"ttl_254"}' 127.0.0.1:8080/api/fault
curl -s -H "$H" -d '{"name":"silent","after":2}' 127.0.0.1:8080/api/behave
curl -s 127.0.0.1:8080/api/status
```

## The behaviours

A script counts its time from the moment the session is Up, or from
the switch when it is already Up. `skip_init` and `fast_while_down`
change what the session's first packets say, so start them with
`POST /api/peer` and `behaviour`.

| Name | What the peer does |
| --- | --- |
| `silent` | stops sending |
| `no_final` | never answers a Poll |
| `fast_while_down` | holds Down and sends every 100 ms |
| `admin_down` | goes AdminDown |
| `flap` | AdminDown and back every second |
| `discr_change` | changes My Discriminator |
| `skip_init` | answers Down with Up |
| `slow_rx` | raises Required Min RX to 1 s |

What RFC 5880 expects of the receiver in each case is in
`BFD::Behaviour::SCRIPTS` and `GET /api/catalog`.

## Events

In bgp4r's shape, as bfdd4r's: `send`, `fault`, `peer`, `behave`,
`session` (a state change of the peer session) and `stop`.
