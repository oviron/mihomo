# Xray-core parity: protocols

Options this fork adds so that mihomo as a client can use what Xray-core
v26.11.9 offers as a server. Key names are the kebab-case form of the Xray JSON
names. Nothing changes unless a key is set.

The checks live in `xraytest/` and run against a real Xray binary:

```sh
XRAY_BIN=/path/to/xray go test -tags with_gvisor -count=1 ./xraytest/
```

## VLESS

### `testseed`

```yaml
- name: vless-vision
  type: vless
  flow: xtls-rprx-vision
  testseed: [900, 500, 900, 256]
```

Same four numbers as the Xray outbound `testseed`. With the key set the XTLS
Vision writer follows Xray-core:

- a block shorter than `testseed[0]` bytes that belongs to a TLS handshake is
  padded to `testseed[2]`..`testseed[2]+testseed[1]` bytes, any other block
  gets 0..`testseed[3]` bytes. Without the key a block of 900 bytes or more is
  sent with no padding at all, which leaves the length of a post-quantum inner
  ClientHello (about 1.2–1.8 KB) visible; `[900, 500, 900, 256]` are Xray's
  defaults, raise the first and the third value above the ClientHello size to
  hide it completely;
- the padding phase ends, and direct copy starts, only when the written data
  consists of whole TLS records. Without the key a record that arrives cut in
  two can start direct copy in the middle of the record.

Fewer than four values mean Xray's defaults.

## XUDP

### `MIHOMO_XUDP_BASEKEY`

Environment variable with 32 random bytes in unpadded URL-safe base64, the
format of Xray's `XRAY_XUDP_BASEKEY` (`head -c 32 /dev/urandom | basenc --base64url | tr -d =`).

The XUDP GlobalID tells the server which UDP flow a new connection continues,
so the server keeps the same outgoing socket. By default it is seeded per
process and a restart loses the mapping. With the key set the ID is a keyed
BLAKE3 hash of the client address, as in Xray, and survives a restart for as
long as the server keeps the flow (one minute after it went idle).

Use a different key on every installation: the server treats a second flow
with the same GlobalID as a reconnect of the first one.

## Mux.Cool

### `mux`

```yaml
- name: vless-xhttp
  type: vless
  # ...
  mux:
    enabled: true
    concurrency: 0            # sessions per connection; 0 = 128
    xudp-concurrency: 0       # > 0: UDP gets connections of its own; < 0: UDP is not multiplexed
    xudp-proxy-udp443: reject # reject | allow | skip
```

Mux.Cool is the multiplexing every Xray inbound accepts: many TCP streams and
UDP associations travel in one connection to the server, addressed to
`v1.mux.cool`. The server needs no setting for it. `mux` works on `vless`,
`vmess`, `trojan`, `ss`, `socks5` and `http` proxies and is not compatible
with `smux` (sing-mux), which an Xray server does not speak.

- `concurrency`: how many sessions share one connection before the next one
  is opened. Xray-core v26.11.9 turns every value from 0 to 128 into 128; here
  0 means 128 and a smaller positive value is honoured. A negative value
  leaves TCP alone. A connection is retired after 1024 sessions and closed
  after 16–32 seconds without one, as in Xray.
- `xudp-concurrency`: 0 puts UDP on the same connections as TCP, a positive
  value gives UDP its own connections with that many sessions each, a negative
  value leaves UDP to the proxy's own transport (XUDP for VLESS and VMess).
- `xudp-proxy-udp443`: what happens to UDP port 443 (QUIC). `reject` is Xray's
  default and makes browsers fall back to TCP; `skip` hands it to the proxy's
  own UDP; `allow` multiplexes it.

UDP sessions carry the XUDP GlobalID, so they are full cone and survive a
reconnect like plain XUDP.

With `flow: xtls-rprx-vision` the server takes no TCP in Mux.Cool. There `mux`
changes nothing but the UDP/443 rule: TCP stays on Vision and UDP on XUDP.

Mux.Cool has no flow control. A session that is not read holds back the other
sessions of its connection; a connection whose peer reads nothing for a minute
is dropped. A half-closed stream ends the session in both directions, as it
does between two Xray instances.

## MASQUE

### Standard CONNECT-IP (`type: masque` without WARP keys)

```yaml
- name: masque
  type: masque
  server: example.org
  port: 443
  user: alice               # the "email" of the Xray client
  pass: secret
  udp: true
  # sni: example.org
  # skip-cert-verify: false
  # host: example.org       # authority of the request, default: sni (and the port if it is not 443)
  # path: /.well-known/masque/ip/*/*/
  # headers: {}
  # mtu: 1280
```

Without `private-key` and `public-key` the `masque` outbound is no longer a
Cloudflare WARP client but a standard MASQUE client (RFC 9484): an extended
CONNECT with the `connect-ip` protocol over HTTP/3, HTTP Basic authentication,
tunnel addresses assigned by the server. That is the `masque` inbound of
Xray-core; `user`, `pass`, `host`, `path` and `headers` are the keys of its
client. `ip` and `ipv6` are not used: the server hands out new addresses on
every connection and the outbound rebuilds its IP stack on them. When the
tunnel is lost, the next connection sets it up again.

On the wire it is HTTP/3 to a web server with a real certificate, and carries
IP packets: TCP and UDP both work, UDP without a full cone guarantee (the
server opens a socket per flow).

### MASQUE over HTTP/2 (`network: h2`)

```yaml
- name: masque-h2
  type: masque
  network: h2
  client-fingerprint: chrome
  # the rest as above
```

The same tunnel over HTTP/2: TCP and TLS all the way, for networks where UDP
does not get through. IP packets travel as DATAGRAM capsules (RFC 9297) in the
bodies of an extended CONNECT. The server is an Xray `masque` inbound whose TLS
settings offer `h2`. `client-fingerprint` makes the TLS handshake that of a
browser.

### TLS and DNS of the tunnel

Both transports take `sni`, `skip-cert-verify`, `fingerprint` (the SHA-256 pin
of the server certificate) and `ech-opts` (`enable`, `config`), with the
meaning they have on other proxies. `remote-dns-resolve: true` with `dns:`
resolves names through the tunnel, like Xray's `remoteDNS`.

Not ported: Xray's `xmux` for MASQUE (several tunnels at once and their
rotation). One outbound keeps one tunnel and sets it up again when it is lost.

## Reverse proxy over VLESS

### `reverse`

```yaml
- name: home
  type: vless
  # ... the account on the server has "reverse": {"tag": "..."}
  reverse:
    tag: from-server
```

The proxy becomes the bridge of an Xray reverse proxy. It is not used for
outgoing connections; instead it keeps a connection to the server open (VLESS
command 4), and the server, the portal, opens Mux.Cool sessions through it.
Whatever the server routes to the outbound named by the account's
`reverse.tag` comes out at this client and is handled like a connection from a
listener named `tag`: rules can match it with `IN-NAME,from-server`. TCP and
UDP both work; it also runs with `flow: xtls-rprx-vision`.

The server asks for another connection when one carries more than 16 sessions
and retires a connection after 256, as between two Xray instances.

What to know before turning it on:

- it lets the server open connections into this network, as far as the rules
  allow. Write rules for `IN-NAME,<tag>`; without them such connections fall
  through to the rules everything else uses;
- the source address of these connections is always `192.0.2.1` (a reserved
  documentation address), never the one the server reports: a reported address
  could match rules meant for local devices and processes;
- a proxy that comes from a provider (a subscription) cannot use `reverse`;
- the proxy is for the bridge only. Xray rejects ordinary connections of an
  account that has `reverse`.
