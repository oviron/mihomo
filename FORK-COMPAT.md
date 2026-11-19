# The layer `compat`

Branch `compat` is branch `utls` plus the fixes below: places where mihomo as a
client disagreed with an Xray-core 26.11.9 server or got something wrong. The
map of the layers, the versions and the move to a new upstream release are in
[FORK.md](FORK.md). Everything here is checked against a real Xray-core
binary, see [Tests](#tests).


## `testseed`: the Vision padding of Xray-core

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

## Options read the way Xray-core writes them

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

## Smaller fixes

- `random` over REALITY with `reality-opts.support-x25519mlkem768` picks only
  among the fingerprints that carry the key share (chrome, safari, firefox).
  Xray answers the `ios` ClientHello, which has none, with the fallback site.
- The SOCKS5 outbound fails a request the server rejected; the reply code used
  to be ignored and the client went on with a garbage address.
- VLESS `encryption` bounds a record by 16640 bytes like Xray-core, not by
  17000.
- `MIHOMO_XUDP_BASEKEY`, an environment variable with 32 random bytes in
  unpadded URL-safe base64, the format of Xray's `XRAY_XUDP_BASEKEY`. With it
  the XUDP GlobalID is a keyed BLAKE3 hash of the client address, as in Xray,
  and survives a restart for as long as the server keeps the flow. By default
  the ID is seeded per process. Use a different key on every installation.

## Tests

`xraytest/` runs the outbounds against a real Xray-core binary. Without
`XRAY_BIN` the tests are skipped.

```sh
docker create --name x ghcr.io/xtls/xray-core:26.11.9 && docker cp x:/usr/local/bin/xray /tmp/xraybin/xray && docker rm x
docker run --rm -v "$PWD":/src -v /tmp/xraybin:/xray:ro -e XRAY_BIN=/xray/xray \
  -w /src -e GOFLAGS=-buildvcs=false \
  golang:1.26 go test -tags with_gvisor -count=1 ./xraytest/ ./transport/...
```

Some of its cases are known gaps: what an Xray-core server offers and this
layer does not speak. They are expected to fail here and pass on `full`.
`.github/workflows/oviron-test.yml` runs the same on every push.
