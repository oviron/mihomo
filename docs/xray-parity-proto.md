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
