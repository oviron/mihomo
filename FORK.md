# oviron/mihomo

Fork of [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) with two
changes:

- TLS fingerprints: `github.com/metacubex/utls` is replaced with
  [oviron/utls](https://github.com/oviron/utls) (MetaCubeX `v1.9.0-alpha.1`
  plus a Firefox 158 parrot and Chrome 155 from refraction-networking/utls).
  See its `FORK.md` for the details.
- [Xray-core compatibility](#xray-core-compatibility): a few places where
  mihomo as a client disagreed with an Xray-core 26.11.9 server.

Branch `oviron` is this fork. Branch `oviron-full` is `oviron` plus the client
side of everything else an Xray-core 26.11.9 server offers (finalmask,
Mux.Cool, MASQUE, XDrive, reverse and more), see [The full line](#the-full-line).

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

## Xray-core compatibility

Checked against a real Xray-core 26.11.9 binary, see [Tests](#tests).

### `testseed`: the Vision padding of Xray-core

```yaml
- name: vless-vision
  type: vless
  flow: xtls-rprx-vision
  testseed: [900, 500, 900, 256]
```

The same four numbers as `testseed` of the Xray VLESS outbound. With the key
set the XTLS Vision writer follows Xray-core:

- a block shorter than `testseed[0]` bytes that belongs to a TLS handshake is
  padded to `testseed[2]`..`testseed[2]+testseed[1]` bytes, any other block
  gets 0..`testseed[3]` bytes. Without the key a block of 900 bytes or more is
  sent with no padding at all, which leaves the length of a post-quantum inner
  ClientHello (about 1.2–1.8 KB) visible. `[900, 500, 900, 256]` are Xray's
  defaults; raise the first and the third value above the ClientHello size to
  hide it completely;
- the padding phase ends, and direct copy starts, only when the written data
  consists of whole TLS records. Without the key a record that arrives cut in
  two can start direct copy in the middle of the record.

Fewer than four values mean Xray's defaults. Without the key nothing changes.

### Options read the way Xray-core writes them

- XHTTP, client and listener: the defaults of the padding obfuscation keys and
  of the uplink data key are Xray's, the upload method is upper-cased, and
  `?query` in `path` goes into the query. An old mihomo and the fork no longer
  match when those keys are left empty with the data placed in headers or
  cookies.
- HTTPUpgrade: `?ed=N` in the path of `v2ray-http-upgrade` turns on fast open
  instead of a WebSocket header the server does not read.
- `reality-opts.client-version: 26.11.9` sets the client version sent to a
  REALITY server, which checks it with `minClientVer` and `maxClientVer`.
  Without the key the version is the one upstream sends.
- `grpc-opts.authority` sets `:authority` apart from the SNI.

### Smaller fixes

- `random` over REALITY with `support-x25519mlkem768` never picks `ios`, see
  the table above.
- The SOCKS5 outbound fails a request the server rejected; the reply code used
  to be ignored and the client went on with a garbage address.
- VLESS `encryption` bounds a record by 16640 bytes like Xray-core, not by
  17000.
- `MIHOMO_XUDP_BASEKEY`, an environment variable with 32 random bytes in
  unpadded URL-safe base64, the format of Xray's `XRAY_XUDP_BASEKEY`. With it
  the XUDP GlobalID is a keyed BLAKE3 hash of the client address, as in Xray,
  and survives a restart for as long as the server keeps the flow. By default
  the ID is seeded per process. Use a different key on every installation.

### Tests

`xraytest/` runs the outbounds against a real Xray-core binary. Without
`XRAY_BIN` the tests are skipped.

```sh
docker create --name x ghcr.io/xtls/xray-core:26.11.9 && docker cp x:/usr/local/bin/xray /tmp/xraybin/xray && docker rm x
docker run --rm -v "$PWD":/src -v /tmp/xraybin:/xray:ro -e XRAY_BIN=/xray/xray \
  -w /src -e GOFLAGS=-buildvcs=false \
  golang:1.26 go test -tags with_gvisor -count=1 ./xraytest/ ./transport/...
```

Some of its cases are known gaps: what an Xray-core server offers and this
branch does not speak. They are expected to fail here and pass on `oviron-full`.

## The full line

Branch `oviron-full` is `oviron` plus one commit with the client side of the
rest of Xray-core 26.11.9: the finalmask masks (`fragment`, `noise`, `sudoku`,
`xmc`, `header-custom`, `salamander`, `udphop`, `xdns`, `xicmp`, `realm`,
`mkcp-legacy`) and `quic-params`, a Mux.Cool client, MASQUE over HTTP/3 and
HTTP/2, `reverse` for VLESS, the `xdrive`, `kcp` and `hysteria` transports,
XHTTP for VMess and Trojan with `xmux` and POST pipelining, `stream-settings`
for Shadowsocks, SOCKS5 and HTTP, `sockopt`, `mldsa65-verify`. Its `FORK.md`
lists every key. None of it is needed to talk to a server as usually set up, so
it stays out of `oviron`: the code is large (about 17 thousand lines) and
`oviron` is meant to stay close to upstream.

The commit-by-commit history of that work is under the tag
`v1.19.34-oviron.3`, the one release of `oviron` that carried all of it. Full
releases are tagged `v<upstream>-oviron.<n>-full`.

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
old=$(git rev-parse oviron)
git rebase --onto vNEW vOLD oviron
go mod tidy && go build ./...
# the tests of the section Tests, against the Xray-core binary
git tag vNEW-oviron.1 && git push origin oviron vNEW-oviron.1
# then the full line, its one commit on top of the new oviron
git rebase --onto oviron "$old" oviron-full
```

When upstream moves to a utls with Firefox 158 and Chrome 155 of its own, the
`replace` can go; the compatibility fixes stay until upstream has them.
