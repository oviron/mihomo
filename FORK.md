# oviron/mihomo

Fork of [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) with two
additions for clients of Xray-core servers:

- TLS fingerprints: `github.com/metacubex/utls` is replaced with
  [oviron/utls](https://github.com/oviron/utls) (MetaCubeX `v1.9.0-alpha.1` plus
  a Firefox 158 parrot and Chrome 155 from refraction-networking/utls). See its
  `FORK.md` for the details.
- [Xray-core parity](#xray-core-parity): the client side of what an Xray-core
  v26.11.9 server offers and upstream mihomo can't connect to. Protocols
  (Mux.Cool, standard MASQUE, the VLESS reverse proxy, Xray's Vision padding),
  transports (XHTTP, mKCP and the hysteria transport under more protocols,
  XDrive, a transport under any protocol) and the finalmask masks.

What that means for `client-fingerprint`:

| value | upstream v1.19.34 | this fork |
|---|---|---|
| `chrome` | Chrome 133 | Chrome 133, same ClientHello |
| `firefox` | Firefox 148, with X25519MLKEM768 | Firefox 158, with X25519MLKEM768 |
| `chrome155` | — | Chrome 155, with X25519MLKEM768 |
| `firefox120` | Firefox 120 | Firefox 120, same ClientHello |
| `safari` | Safari 26.3 | Safari 26.3 |
| `random` | chrome, safari, ios, firefox weighted 6/3/2/1, picked once per process | same weights, with the `firefox` above; over REALITY with `support-x25519mlkem768` never `ios` |

Firefox 158 is the ClientHello of current Firefox stable in normal browsing mode.
It carries X25519MLKEM768, so Xray REALITY servers from 26.9 on accept it. Over
REALITY, mihomo strips that key share unless the proxy sets
`reality-opts.support-x25519mlkem768: true`, in upstream and here alike.
With that option `random` picks only among the fingerprints that carry the key
share (chrome, safari, firefox): Xray answers the `ios` ClientHello, which has
none, with the fallback site.

`chrome155` is the one name the fork adds: Chrome 155 on macOS as
refraction-networking/utls captured it, the default fingerprint of Xray-core
v26.11.9. Its BoringSSL GREASE ECH payload length varies per connection like the
browser's. `chrome` stays Chrome 133.

The utls key share fix also changes one thing for the unchanged ClientHellos:
fingerprints that offer X25519 and P-256 shares, such as `firefox120`, now finish
the handshake when the server picks P-256 instead of failing.

## Xray-core parity

mihomo as a client of an Xray-core v26.11.9 server. Everything below is turned
on by a key; without the new keys the fork behaves like upstream, with the
exceptions listed in [What changed without a key](#what-changed-without-a-key).
Keys are the kebab-case form of the names Xray-core uses in JSON.

| YAML key | on | Xray-core JSON |
|---|---|---|
| `testseed` | vless | `settings.testseed` of the VLESS outbound |
| `reverse: {tag}` | vless | `settings.reverse.tag` of the VLESS outbound |
| `mux: {enabled, concurrency, xudp-concurrency, xudp-proxy-udp443}` | vless, vmess, trojan, ss, socks5, http | `mux: {enabled, concurrency, xudpConcurrency, xudpProxyUDP443}` of the outbound |
| `MIHOMO_XUDP_BASEKEY` (environment) | process | `XRAY_XUDP_BASEKEY` |
| `user`, `pass`, `host`, `path`, `headers` without `private-key` | masque | `masqueSettings.{user, pass, host, path, headers}` |
| `network: h2` | masque | `masqueSettings` over TLS with ALPN `h2` |
| `remote-dns-resolve` with `dns` | masque | `settings.remoteDNS` of the MASQUE outbound |
| `stream-settings` | any proxy | `streamSettings` |
| `network: xhttp` | vless, vmess, trojan, `stream-settings` | `network: xhttp` |
| `xhttp-opts.xmux` | xhttp | `xhttpSettings.extra.xmux` |
| `xhttp-opts.pipeline-posts` | xhttp | none, the Xray client always does it |
| `xhttp-opts.download-settings.{xmux, x-padding-*, session-*, seq-*}` | xhttp | `downloadSettings.xhttpSettings` |
| `xhttp-opts.download-settings.finalmask` | xhttp | `downloadSettings.finalmask` |
| `network: kcp`, `mkcp-opts` | vless, vmess, trojan, `stream-settings` | `network: kcp`, `kcpSettings` |
| `mkcp-opts.raw` | kcp | none, Xray-core 26 has no other mKCP |
| `network: hysteria`, `hysteria-opts: {version, auth}` | vless, vmess, trojan | `network: hysteria`, `hysteriaSettings: {version, auth}` |
| `network: xdrive`, `xdrive-opts` | vless | `network: xdrive`, `xdriveSettings` |
| `tls: false` | trojan | `security: none` |
| `reality-opts.mldsa65-verify` | REALITY | `realitySettings.mldsa65Verify` |
| `reality-opts.client-version` | REALITY | none, an Xray client sends its own version; the server checks it with `minClientVer` and `maxClientVer` |
| `fingerprint`, a list | TLS | `tlsSettings.pinnedPeerCertSha256` |
| `name-cert-verify`, a list | TLS | `tlsSettings.verifyPeerCertByName` |
| `grpc-opts.authority` | grpc | `grpcSettings.authority` |
| `grpc-user-agent: chrome` | grpc | `grpcSettings.user_agent` |
| `ws-opts.headers.User-Agent: chrome` | ws, httpupgrade | `wsSettings.headers.User-Agent` |
| `sockopt.{tcp-keep-alive-idle, tcp-keep-alive-interval, tcp-user-timeout, tcp-max-seg, tcp-window-clamp, tcp-congestion}` | any proxy | `sockopt.{tcpKeepAliveIdle, tcpKeepAliveInterval, tcpUserTimeout, tcpMaxSeg, tcpWindowClamp, tcpCongestion}` |
| `sockopt.address-port-strategy` | any proxy | `sockopt.addressPortStrategy` |
| `finalmask: {tcp, udp, quic-params}` | any proxy | `streamSettings.finalmask: {tcp, udp, quicParams}` |

What mihomo already had under another name: `routing-mark` (`sockopt.mark`),
`interface-name` (`interface`), `tfo` (`tcpFastOpen`), `mptcp` (`tcpMptcp`),
`dialer-proxy` (`dialerProxy`), `ip-version` (`domainStrategy`),
`xhttp-opts.reuse-settings` (`xmux` with upstream's counting),
`ws-opts.v2ray-http-upgrade` (`network: httpupgrade`),
`network: http` with `http-opts` (RAW with `header: http`).

### Protocols

#### `testseed`: the Vision padding of Xray-core

```yaml
- name: vless-vision
  type: vless
  flow: xtls-rprx-vision
  testseed: [900, 500, 900, 256]
```

**The fix is off until the key is set.** Without `testseed` the XTLS Vision
writer is upstream's, and differs from Xray-core in two ways:

- a block of 900 bytes or more is sent with no padding at all, which leaves
  the length of a post-quantum inner ClientHello (about 1.2–1.8 KB) visible;
- direct copy can start in the middle of a TLS record when the record arrives
  cut in two.

With the key the writer follows Xray-core: a block shorter than `testseed[0]`
bytes that belongs to a TLS handshake is padded to
`testseed[2]`..`testseed[2]+testseed[1]` bytes, any other block gets
0..`testseed[3]` bytes, and the padding phase ends only when the written data
consists of whole TLS records. `[900, 500, 900, 256]` are Xray's defaults, and
what fewer than four values mean; raise the first and the third value above
the ClientHello size to hide it completely.

#### `MIHOMO_XUDP_BASEKEY`

Environment variable with 32 random bytes in unpadded URL-safe base64, the
format of Xray's `XRAY_XUDP_BASEKEY` (`head -c 32 /dev/urandom | basenc --base64url | tr -d =`).

The XUDP GlobalID tells the server which UDP flow a new connection continues,
so the server keeps the same outgoing socket. By default it is seeded per
process and a restart loses the mapping. With the key set the ID is a keyed
BLAKE3 hash of the client address, as in Xray, and survives a restart for as
long as the server keeps the flow (one minute after it went idle). Use a
different key on every installation: the server treats a second flow with the
same GlobalID as a reconnect of the first one.

#### `mux`: Mux.Cool

```yaml
- name: vless-ws
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
`vmess`, `trojan`, `ss`, `socks5` and `http` proxies, over any transport and
over `finalmask`, and is not compatible with `smux` (sing-mux), which an Xray
server does not speak.

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

Two cases where an Xray server takes no TCP in Mux.Cool and `mux` leaves TCP
alone:

- `flow: xtls-rprx-vision`: TCP stays on Vision and UDP on XUDP, `mux` changes
  nothing but the UDP/443 rule;
- XHTTP (`network: xhttp`, also in `stream-settings`): an XHTTP inbound takes
  only UDP sessions, as XHTTP multiplexes the streams itself. TCP goes over
  XHTTP as without `mux`, UDP is multiplexed.

Mux.Cool has no flow control. A session that is not read holds back the other
sessions of its connection; a connection whose peer reads nothing for a minute
is dropped. A half-closed stream ends the session in both directions, as it
does between two Xray instances.

#### Standard MASQUE (`type: masque` without WARP keys)

```yaml
- name: masque
  type: masque
  server: example.org
  port: 443
  user: alice               # the "email" of the Xray client
  pass: secret
  udp: true
  # network: h2             # over HTTP/2 instead of HTTP/3
  # client-fingerprint: chrome   # for network: h2
  # sni: example.org
  # skip-cert-verify: false
  # host: example.org       # authority of the request, default: sni (and the port if it is not 443)
  # path: /.well-known/masque/ip/*/*/
  # headers: {}
  # mtu: 1280
```

Without `private-key` and `public-key` the `masque` outbound is not a
Cloudflare WARP client but a standard MASQUE client (RFC 9484): an extended
CONNECT with the `connect-ip` protocol, HTTP Basic authentication, tunnel
addresses assigned by the server. That is the `masque` inbound of Xray-core.
`ip` and `ipv6` are not used: the server hands out new addresses on every
connection and the outbound rebuilds its IP stack on them. When the tunnel is
lost, the next connection sets it up again.

On the wire it is HTTP/3 to a web server with a real certificate, and carries
IP packets: TCP and UDP both work, UDP without a full cone guarantee (the
server opens a socket per flow). `network: h2` is the same tunnel over HTTP/2,
TCP and TLS all the way, for networks where UDP does not get through: the IP
packets travel as DATAGRAM capsules (RFC 9297) in the bodies of the CONNECT,
and the server is a `masque` inbound whose TLS settings offer `h2`.

Both take `sni`, `skip-cert-verify`, `fingerprint` (the SHA-256 pin of the
server certificate) and `ech-opts`, with the meaning they have on other
proxies. `remote-dns-resolve: true` with `dns:` resolves names through the
tunnel, like Xray's `remoteDNS`. Xray's `xmux` for MASQUE (several tunnels and
their rotation) is not ported: one outbound keeps one tunnel.

#### `reverse`: the bridge of a VLESS reverse proxy

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

What to know before turning it on:

- it lets the server open connections into this network, as far as the rules
  allow. Write rules for `IN-NAME,<tag>`; without them such connections fall
  through to the rules everything else uses;
- the source address of these connections is always `192.0.2.1` (a reserved
  documentation address), never the one the server reports: a reported address
  could match rules meant for local devices and processes;
- every destination of a UDP session is an association of its own, so the
  rules are asked for each of them; UDP through the bridge is not full cone,
  and a session reaches at most 64 destinations;
- the bridge connects only while its proxy is part of the running config: not
  for a config that failed to load, and its connections are closed within
  seconds after a reload dropped or replaced the proxy;
- a proxy that comes from a provider (a subscription) cannot use `reverse`;
- the proxy is for the bridge only. Xray rejects ordinary connections of an
  account that has `reverse`.

### Transports and security

#### `stream-settings`: a transport under any protocol

```yaml
- name: ss-behind-reality
  type: ss
  # ...
  stream-settings:
    network: xhttp          # raw (default), ws, httpupgrade, grpc, xhttp, kcp
    tls: true
    servername: example.org
    client-fingerprint: chrome
    reality-opts: {public-key: ..., short-id: ...}
    xhttp-opts: {path: /xh, mode: stream-up}
```

Xray-core has `streamSettings` on every inbound, so a Shadowsocks, SOCKS or
HTTP server may sit behind TLS, REALITY, WebSocket, gRPC, XHTTP or mKCP. This
block is the client side for the proxies that have no transport options of
their own; it takes the option names of VLESS (`tls`, `alpn`, `servername`,
`skip-cert-verify`, `fingerprint`, `client-fingerprint`, `ech-opts`,
`reality-opts`, `ws-opts`, `grpc-opts`, `xhttp-opts`, `mkcp-opts`). VLESS,
VMess and Trojan keep their own options and refuse the block.

Only the TCP side goes over the transport, as on the server: such a proxy is
set up without `udp`. The security belongs in the block, not in the `tls`
option of the SOCKS and HTTP proxies, which would be a second TLS inside.
SOCKS over a UDP based transport (kcp, XHTTP over HTTP/3) crashes Xray-core
v26.11.9 itself.

#### XHTTP

- `network: xhttp` with `xhttp-opts` works on VMess and Trojan as on VLESS.
- `xmux` is the connection pool with the semantics of Xray-core:
  `max-concurrency`, `max-connections`, `c-max-reuse-times`,
  `h-max-request-times` counted per request, `h-max-reusable-secs`,
  `h-keep-alive-period`. An empty `xmux: {}` gives Xray's defaults.
  `reuse-settings` of upstream stays as it was.
- `pipeline-posts: true` sends the POSTs of `packet-up` without waiting for
  the answer to the previous one, like the Xray client, which makes uploads
  faster. It expects the server to buffer at least 16 posts
  (`scMaxBufferedPosts`, 30 by default).
- `download-settings` takes its own `xmux`, `x-padding-*`, `session-*` and
  `seq-*` keys and its own `finalmask`.

#### mKCP

`network: kcp` with `mkcp-opts` works on VLESS and Trojan as on VMess, and in
`stream-settings`. Against Xray-core 26 it needs `mkcp-opts: {raw: true}`, see
[finalmask](#finalmask). On VLESS, Trojan and `stream-settings` a `tti`
outside 10–1000 is rejected when the config is loaded.

#### The hysteria transport

```yaml
- name: vless-over-hysteria
  type: vless
  # ...
  network: hysteria
  tls: true
  hysteria-opts: {version: 2, auth: secret}
```

The proxy protocol runs in the streams of a Hysteria 2 connection: the
`hysteria` transport of Xray-core under a VLESS, VMess or Trojan inbound, not
the `hysteria2` outbound. `finalmask` gives it `salamander`, `udphop` and
`quic-params`.

#### XDrive

```yaml
- name: vless-xdrive
  type: vless
  encryption: mlkem768x25519plus...   # required, a flow is not allowed
  network: xdrive
  xdrive-opts:
    service: s3              # s3, template or local
    remote-folder: tunnel
    secrets: [ACCESS_KEY_ID, SECRET_ACCESS_KEY]
    s3: {endpoint: https://s3.example.org, region: auto, bucket: name}
```

The stream goes through objects in a storage both ends can reach; the client
never connects to the server. `server` and `port` of the proxy are not dialed,
the storage is reached at its own address through the proxy's dialer and with
its TLS options. `template` describes any HTTP storage the way Xray-core does,
with Xray's own keys. Not ported: the Google Drive service, and `xmux`,
HTTP/3 and domain fronting for the requests to the storage. Checked against
MinIO; not against AWS S3 or Cloudflare R2.

#### TLS, REALITY, gRPC, WebSocket

- `tls: false` on a Trojan proxy is Trojan without TLS, which Xray-core serves
  too. It can't be combined with REALITY.
- `reality-opts.mldsa65-verify` checks the ML-DSA-65 signature of a REALITY
  server that has `mldsa65Seed`; the value is the "Verify" key `xray mldsa65`
  prints. It needs a build with Go 1.27, which the release workflow uses; in a
  build with an older Go the key is a config error.
- `reality-opts.client-version: 26.11.9` sets the client version sent to a
  REALITY server that has `minClientVer` or `maxClientVer`. The default stays
  upstream's 1.8.2.
- `fingerprint` and `name-cert-verify` take comma separated lists, for a
  certificate that is about to be replaced.
- `grpc-opts.authority` sets `:authority` apart from the SNI.
  `grpc-user-agent` and `ws-opts.headers.User-Agent` take the browser names of
  Xray-core (`chrome`, `firefox`, `edge`, `golang`; for WebSocket and
  HTTPUpgrade also `safari` and `curl`) and send that browser's header set.
  Without the key a WebSocket request goes out as `Go-http-client/1.1`, which
  an Xray client never sends: add `User-Agent: chrome` to look like one.
- The name of a gRPC service is sent as written: write it URL-escaped if the
  server's name needs escaping, and `grpc-service-name: "//Tun"` for a server
  with an empty `serviceName`.

#### `sockopt`

```yaml
- name: example
  # ...
  sockopt:
    tcp-keep-alive-idle: 30      # seconds, negative turns keep-alive off
    tcp-keep-alive-interval: 10
    tcp-user-timeout: 10000      # milliseconds
    tcp-max-seg: 1360
    tcp-window-clamp: 600
    tcp-congestion: bbr
    address-port-strategy: srvportandaddress
```

The TCP socket options of Xray-core for the connections to the proxy's server;
they work on Linux. `address-port-strategy` takes the address, the port or
both from a SRV or TXT record of `server` (`srvportonly`, `srvaddressonly`,
`srvportandaddress`, `txtportonly`, `txtaddressonly`, `txtportandaddress`).
Nothing of `sockopt` applies with `dialer-proxy`, and `address-port-strategy`
not to VLESS over XHTTP/3.

### finalmask

Every proxy takes a `finalmask` option, the `streamSettings.finalmask` of
Xray-core: masks applied to the TCP connection or the UDP socket the proxy
opens to its server, below TLS and below any UDP based transport.

```yaml
proxies:
  - name: example
    type: vless
    # ...
    finalmask:
      tcp:
        - type: fragment
          settings: {packets: tlshello, length: 100-200, delay: 10-20}
      udp:
        - type: noise
          settings: {noise: [{rand: 50-100, delay: 5-10}]}
        - type: salamander
          settings: {password: secret}
      quic-params: {congestion: bbr}
```

Keys are the kebab-case form of the names Xray-core uses in JSON, and the
original names (`maxSplit`, `remoteIPs`, `custom_table`) are accepted too, so
the `finalmask` object of an Xray config can be pasted as it is. As in
Xray-core the last mask of a list is the one closest to the wire. A broken
option is rejected when the config is loaded.

| mask | where | what it does |
|---|---|---|
| `fragment` | tcp | splits the TLS ClientHello into several TLS records, or the chosen writes into small TCP segments; the server needs no setting |
| `header-custom` | tcp, udp | a configurable exchange of bytes before the data (tcp), or a header on every datagram or a datagram of its own (udp) |
| `sudoku` | tcp, udp | recodes the stream or every datagram into the bytes of sudoku hints |
| `xmc` | tcp | the connection starts like a Minecraft client logging in, then carries the data in plugin messages |
| `noise` | udp | junk datagrams ahead of the first packet, from a list or from a Lua script; the server needs no setting |
| `salamander` | udp | the obfuscation of Hysteria 2 for any UDP transport; with `packet-size` it is Gecko |
| `mkcp-legacy` | udp | the obfuscation and the fake headers mKCP had built in before Xray-core 26 |
| `udphop` | udp | port hopping for any UDP transport; the server needs no setting |
| `xdns` | udp | carries the datagrams in DNS queries through public resolvers |
| `xicmp` | udp | carries the datagrams in ICMP echo; `dgram: true` needs no root, which is the only way on Android |
| `realm` | udp | reaches a server behind NAT through a rendezvous server and hole punching |

`quic-params` is local tuning of every QUIC connection the proxy makes to its
server: the hysteria2 outbound, the hysteria transport, XHTTP over HTTP/3 and
MASQUE over HTTP/3. It sets congestion control (`reno`, `bbr`, `brutal`,
`force-brutal`), `brutal-up`, `brutal-down`, `bbr-profile`, receive windows,
`max-idle-timeout`, `keep-alive-period`, `disable-path-mtu-discovery`. MASQUE
carries IP packets in datagrams and takes no `brutal`, only `force-brutal`.

What goes with it:

- `mkcp-opts: {raw: true}` sends bare mKCP, which is what Xray-core 26 speaks:
  its obfuscation is all in `mkcp-legacy`. Without `raw` mihomo's mKCP keeps
  its built-in `seed` and `header`, which equal the masks
  `[{type: mkcp-legacy, settings: {value: seed}}, {type: mkcp-legacy, settings: {header: ...}}]`.
  A `mkcp-legacy` mask without `raw`, or `raw` together with `seed` or
  `header`, would obfuscate twice and is rejected when the config is loaded.
- `obfs` and `ports` of the hysteria2 outbound stay; they are the `salamander`
  and `udphop` masks for Hysteria only.
- The masks apply to the connection to the proxy's server. The download server
  of XHTTP has a `finalmask` of its own in `download-settings`, like
  `downloadSettings.finalmask` of Xray-core, and is dialed without masks when
  that key is absent. The realm rendezvous server of Hysteria 2 is dialed
  without them.
- With `stream-settings` the masks stay the last layer before the wire, under
  the transport; a connection that does not go to the proxy's server leaves
  out both.
- `xicmp` opens ICMP sockets, not through the proxy's dialer: a proxy with it
  can't have `dialer-proxy`, `interface-name` or `routing-mark`. UDP masks can't
  be combined with `realm-opts` of the hysteria2 outbound, and `udphop`,
  `xdns`, `xicmp` and `realm`, which pick where to send, not with its `ports`.
- `tls-config` of `realm` and of the HTTPS resolvers of `xdns` takes
  `server-name`, `alpn`, `pinned-peer-cert-sha256` and
  `verify-peer-cert-by-name`. Any other field that is set, `allowInsecure`
  included, is rejected.
- With `tfo: true` and TCP masks the connection is made before the first write.

Not carried over from Xray-core:

- The server halves of the masks, and `filter`, which filters the clients of
  a server. `filter` is accepted and ignored.
- `realm.portMapping` (UPnP and NAT-PMP): it needs five more modules, whose
  sockets would not go through mihomo's dialer.
- The Chrome fingerprint of the QUIC handshake (`disableChromeParrot` turns it
  off in Xray-core): it lives in Xray-core's fork of quic-go. `disableGSO` and
  `brutalDisableLossCompensation` would need changes in quic-go and sing-quic
  as well. All three keys are accepted and ignored.

The code is in `transport/finalmask`, one package per mask, and touches the
upstream files in a few lines each: `adapter/outbound/base.go` (the option
and the wrapped dialer), `adapter/parser.go` (the check at load),
`adapter/outbound/hysteria2.go`, `masque.go` and `vless.go` (`quic-params`,
the download leg), `adapter/outbound/vmess.go` and `transport/mkcp` (`raw`),
and one new file in `transport/sudoku/obfs/sudoku` (read access to its
tables).

The noise scripts add one module to `go.mod`, `github.com/yuin/gopher-lua`
v1.1.1 (later versions need a newer Go than `go.mod` declares).

### What changed without a key

- XHTTP, client and listener: the defaults of the padding obfuscation keys and
  of the uplink data key are Xray's, the upload method is upper-cased, and
  `?query` in `path` goes into the query. An old mihomo and the fork no longer
  match when those keys are left empty with the data placed in headers or
  cookies.
- HTTPUpgrade: `?ed=N` in the path of `v2ray-http-upgrade` turns on fast open
  instead of a WebSocket header the server does not read.
- `random` over REALITY with `support-x25519mlkem768` never picks `ios`.
- `download-settings.reuse-settings` works without `reuse-settings` of the
  upload leg.
- `grpc-user-agent: chrome` (`firefox`, `edge`, `golang`) and
  `User-Agent: chrome` (`firefox`, `safari`, `edge`, `curl`, `golang`) in
  `ws-opts.headers` are the browser names of Xray-core; they used to be sent as
  the literal value.
- `type: masque` without `private-key` and `public-key` used to be a config
  error and is now the standard MASQUE client.
- The SOCKS5 outbound fails a request the server rejected; the reply code
  used to be ignored. VLESS `encryption` bounds a record by 16640 bytes like
  Xray-core, not by 17000.

### Xray-core behaviour worth knowing

Found while testing against v26.11.9, for whoever configures the server:

- `xmc`: a `password` of 33 to 40, 49 to 56, 65 to 72, 81 to 88, 97 to 104 or
  113 bytes does not work. The server derives an RSA key from it that Go
  refuses (`crypto/rsa: |p - q| too small`) and drops every connection. A
  36-character UUID is such a password. mihomo warns about it in the log.
- `xdns` with resolvers of type `tcp`: Xray-core's own client sends the DNS
  messages without the length prefix. mihomo sends it.
- `xdns` and the mKCP `mtu` of the server: the server drops a datagram of
  its own that does not fit into a DNS answer (`err size` in its log) and
  mKCP has to send the data again, which costs speed. Nothing is
  negotiated, so `kcpSettings.mtu` of the server has to leave room: the size
  of the answer to the longest query, less 2 bytes, less what the masks below
  mKCP add, 6 bytes for `mkcp-legacy` and 28 when it has a seed (`value`).
  The answer is as large as the smaller of the server's `edns0` and the size
  the query announces, which is the `edns0` of the client or that of a
  resolver in between, which makes its own queries. With TXT records that
  makes 926 when both are 1232 (904 with a seed) and 220 when the query has
  no EDNS (198 with a seed). The client needs no such limit on its `mtu`:
  the mask splits a datagram over as many queries as it takes.
- `header-custom` over UDP in `prefix` mode: when the server echoes a value
  the client makes anew for every datagram, most of what the server sends is
  dropped as soon as datagrams overlap, since each end keeps only the last
  value. This is how the mask is defined; use it for values that stay.
- Mux.Cool: an inbound with `flow: xtls-rprx-vision` accounts, or on the XHTTP
  or MASQUE transport, takes only UDP sessions and drops the whole connection
  on a TCP one. The server does not pass a half-close on.
- `freedom` blocks private and loopback targets for traffic from a proxy
  inbound unless it has `finalRules: [{action: allow}]`.
- A SOCKS inbound on a UDP based transport (kcp, XHTTP over HTTP/3) panics on
  the first connection.
- XHTTP `stream-up` and `stream-one` over HTTP/1.1 break on the server.
- mKCP is bare since Xray-core 26: a client with the old built-in
  obfuscation, which is mihomo without `raw: true`, is not understood.

### Tests

`xraytest/` runs every key above against a real Xray-core binary, and XDrive
against MinIO. Without `XRAY_BIN` the tests are skipped.

```sh
docker create --name x ghcr.io/xtls/xray-core:26.11.9 && docker cp x:/usr/local/bin/xray /tmp/xraybin/xray && docker rm x
docker create --name m cgr.dev/chainguard/minio && docker cp m:/usr/bin/minio /tmp/xraybin/minio && docker rm m
docker run --rm -v "$PWD":/src -v /tmp/xraybin:/xray:ro -e XRAY_BIN=/xray/xray -e MINIO_BIN=/xray/minio \
  --sysctl net.ipv4.ping_group_range="0 2147483647" -w /src -e GOFLAGS=-buildvcs=false \
  golang:1.27 go test -tags with_gvisor -count=1 ./xraytest/ ./transport/...
```

## Versions

Branch `oviron` sits on an upstream release tag. A fork release is tagged
`v<upstream>-oviron.<n>` (for example `v1.19.34-oviron.1`), and `mihomo -v` prints
that tag. Pushing such a tag runs `.github/workflows/oviron-release.yml`, which
publishes gzipped `linux-arm64` and `darwin-arm64` binaries named like upstream
assets (`mihomo-linux-arm64-<tag>.gz`) with `SHA256SUMS`. The upstream build
workflows are disabled in this repository.

## New upstream release

```sh
git fetch upstream --tags
git rebase --onto vNEW vOLD oviron
go mod tidy && go build ./...
git tag vNEW-oviron.1 && git push origin oviron vNEW-oviron.1
```

When upstream moves to a utls with Firefox 158 of its own, the fork is no longer
needed.
