# oviron/mihomo

Fork of [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) with two
additions for clients of Xray-core servers:

- TLS fingerprints: `github.com/metacubex/utls` is replaced with
  [oviron/utls](https://github.com/oviron/utls) (MetaCubeX `v1.9.0-alpha.1` plus
  a Firefox 158 parrot and Chrome 155 from refraction-networking/utls). See its
  `FORK.md` for the details.
- [Xray-core finalmask](#xray-core-finalmask), the client side: the masks an
  Xray-core v26.11.9 server can put under its transports.

What that means for `client-fingerprint`:

| value | upstream v1.19.34 | this fork |
|---|---|---|
| `chrome` | Chrome 133 | Chrome 133, same ClientHello |
| `firefox` | Firefox 148, with X25519MLKEM768 | Firefox 158, with X25519MLKEM768 |
| `chrome155` | — | Chrome 155, with X25519MLKEM768 |
| `firefox120` | Firefox 120 | Firefox 120, same ClientHello |
| `safari` | Safari 26.3 | Safari 26.3 |
| `random` | chrome, safari, ios, firefox weighted 6/3/2/1, picked once per process | same weights, with the `firefox` above |

Firefox 158 is the ClientHello of current Firefox stable in normal browsing mode.
It carries X25519MLKEM768, so Xray REALITY servers from 26.9 on accept it. Over
REALITY, mihomo strips that key share unless the proxy sets
`reality-opts.support-x25519mlkem768: true`, in upstream and here alike.

`chrome155` is the one name the fork adds: Chrome 155 on macOS as
refraction-networking/utls captured it, the default fingerprint of Xray-core
v26.11.9. Its BoringSSL GREASE ECH payload length varies per connection like the
browser's. `chrome` stays Chrome 133.

The utls key share fix also changes one thing for the unchanged ClientHellos:
fingerprints that offer X25519 and P-256 shares, such as `firefox120`, now finish
the handshake when the server picks P-256 instead of failing.

## Xray-core finalmask

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

`quic-params` is local tuning of the QUIC connection of the hysteria2 outbound
and of XHTTP over HTTP/3: congestion control (`reno`, `bbr`, `brutal`,
`force-brutal`), `brutal-up`, `brutal-down`, `bbr-profile`, receive windows,
`max-idle-timeout`, `keep-alive-period`, `disable-path-mtu-discovery`.

What goes with it:

- `mkcp-opts: {raw: true}` sends bare mKCP, which is what Xray-core 26 speaks:
  its obfuscation is all in `mkcp-legacy`. Without `raw` mihomo's mKCP keeps
  its built-in `seed` and `header`, which equal the masks
  `[{type: mkcp-legacy, settings: {value: seed}}, {type: mkcp-legacy, settings: {header: ...}}]`.
- `obfs` and `ports` of the hysteria2 outbound stay; they are the `salamander`
  and `udphop` masks for Hysteria only.
- The masks apply to the connection to the proxy's server. The download server
  of XHTTP and the realm rendezvous server of Hysteria 2 are dialed without them.
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

Known behaviour of Xray-core v26.11.9 worth knowing when you configure a server:

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

The code is in `transport/finalmask`, one package per mask, and touches the
upstream files in a few lines each: `adapter/outbound/base.go` (the option
and the wrapped dialer), `adapter/parser.go` (the check at load),
`adapter/outbound/hysteria2.go` and `vless.go` (`quic-params`, unmasked
dials), `adapter/outbound/vmess.go` and `transport/mkcp` (`raw`), and one new
file in `transport/sudoku/obfs/sudoku` (read access to its tables).
`xraytest` checks every mask against a real Xray-core binary:

```sh
docker create --name x ghcr.io/xtls/xray-core:26.11.9 && docker cp x:/usr/local/bin/xray /tmp/xray && docker rm x
docker run --rm -v "$PWD":/src -v /tmp/xray:/xray:ro -e XRAY_BIN=/xray \
  --sysctl net.ipv4.ping_group_range="0 2147483647" -w /src -e GOFLAGS=-buildvcs=false \
  golang:1.26 go test -tags with_gvisor -count=1 ./xraytest/ ./transport/finalmask/...
```

The noise scripts add one module to `go.mod`, `github.com/yuin/gopher-lua`
v1.1.1 (later versions need a newer Go than `go.mod` declares).

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
