# Building objects

How to build, read and check BFD packets with bfd4r. It follows bgp4r's
and vtep4r's guides of the same name. `test/unit/docs/building_objects_test.rb`
runs every example here and checks each `# =>` result, and checks that
the list of classes below is the list in the code.

## The classes

Every class that encodes a part of a packet:

- `BFD::Control`
- `BFD::Auth::Password`
- `BFD::Auth::Md5`
- `BFD::Auth::Sha1`
- `BFD::Auth::Unknown`

`BFD::Control` is the packet of RFC 5880 4.1. The other four are its
Authentication Section (4.2 to 4.4), found by Auth Type through
`BFD::Auth.new`. A type no class reads, or a section too short for its
type's fields, is kept whole as `BFD::Auth::Unknown`.

## Four ways in

Each class is built from field values, a hash, its wire bytes or
another instance. All four give the same object, and the same `encode`
is the measure.

```ruby
up = BFD::Control.new(state: :up, my_discr: 7, your_discr: 9,
                      desired_min_tx: 300_000, required_min_rx: 300_000)
up.to_shex                    # => "20c00318000000070000000900" + "0493e0000493e000000000"
BFD::Control.new(up.to_hash) == up   # => true
BFD::Control.new(up.encode) == up    # => true
BFD::Control.new(up) == up           # => true
```

A String is always wire bytes. Intervals are in microseconds, as on the
wire. The state and diagnostic take the names of RFC 5880 4.1, or their
numbers.

```ruby
BFD::Control.new(state: 3, diag: 0, my_discr: 7) == BFD::Control.new(state: :up, diag: :none, my_discr: 7)   # => true
```

## Reading

`to_hash` gives back what built the object. A field at its default is
left out, but for the state, the discriminators and the two intervals.
`to_s` is tcpdump's line, then the discriminators.

```ruby
up.to_hash   # => { state: :up, my_discr: 7, your_discr: 9, desired_min_tx: 300_000, required_min_rx: 300_000 }
up.to_s      # => "BFDv1, Control, State Up, Flags: [none], length: 24, my 0x00000007, your 0x00000009"
```

## Building is never validated

bfd4r is for negative tests. Any version, flag, length or interval goes
out as asked. Length and the A bit are worked out unless given, so a
packet can lie about either. Only a value too wide for its field is
refused, since another value would go out in its place.

```ruby
bad = BFD::Control.new(state: :up, my_discr: 7, your_discr: 9, version: 2, multipoint: true, length: 23)
bad.length        # => 23
bad.multipoint?   # => true
BFD::Control.new(detect_mult: 256) rescue $!.class   # => ArgumentError
```

A packet read from the wire keeps every bit and writes it back,
octets after its Authentication Section included, as the trailer.

## Authentication

A section is a hash under `auth:`, with its `type`. Md5 and Sha1 carry
a digest of zeros until `signed` puts in the right one for a key
(RFC 5880 6.7.3, 6.7.4).

```ruby
sha1 = BFD::Control.new(state: :down, my_discr: 7,
                        auth: { type: :meticulous_keyed_sha1, key_id: 7, sequence: 1 })
sha1.length                    # => 52
sha1.auth.class                # => BFD::Auth::Sha1
signed = sha1.signed('secret')
signed.auth.digest == sha1.auth.digest   # => false
```

A wrong digest, a wrong Auth Len or a password of any length go out as
asked:

```ruby
BFD::Auth.new(type: :simple_password, key_id: 1, password: 'x', auth_len: 9).to_shex   # => "01090178"
```

## Checking what was received

`BFD::Validation` holds the receive rules of RFC 5880 6.8.6 and RFC
5881 5, each a named finding with its section. Rules that need a
session's state are checked when it is given: `known:` discriminators,
`auth:` (false when none is in use), `ttl:` and `payload:`.

```ruby
BFD::Validation.check(bad).map(&:name)   # => [:bad_version, :short, :multipoint]
BFD::Validation.check(up, ttl: 254).first.to_s   # => "ttl_not_255: TTL 254 (RFC 5881 5) (discard)"
BFD::Validation.check(signed, auth: { type: :meticulous_keyed_sha1, keys: { 7 => 'secret' } })   # => []
```

A receive policy turns findings into a verdict: `:rfc`, the default,
discards what the RFCs discard; `:strict` raises `BFD::Malformed_packet`
on any finding; `:lenient` accepts all.

```ruby
BFD::Validation.decide(bad)                       # => :discard
BFD::Validation.decide(bad, policy: :lenient)     # => :accept
BFD::Validation.decide(up, ttl: 1, policy: :rfc)  # => :discard
```
