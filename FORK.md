# oviron/mihomo

Fork of [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) for clients of
Xray-core servers. It is three layers, each a branch that sits on the one
before it and adds one thing:

| Branch | Adds | Described in | Size |
|---|---|---|---|
| `utls` | on upstream: the TLS fingerprints of [oviron/utls](https://github.com/oviron/utls) | this file | a `replace` and one name |
| `compat` | on `utls`: fixes where mihomo as a client disagreed with an Xray-core 26.11.9 server | `FORK-COMPAT.md` | about 460 lines |
| `full` | on `compat`: the client side of everything else such a server offers (finalmask, Mux.Cool, MASQUE, XDrive, reverse and more) | `FORK-FULL.md` | about 17 thousand lines |

`compat` is the default branch and the one in daily use. `full` is for a
server that has one of its features turned on; it is kept in step so that it
is ready when needed. `utls` alone is upstream with other fingerprints.

What goes where: a fix of something the client already does belongs to
`compat`, a new feature to `full`, and `utls` takes nothing but fingerprints.
A layer does not edit the `FORK*.md` of the layers below it.

## Fingerprints

`github.com/metacubex/utls` is replaced with
[oviron/utls](https://github.com/oviron/utls) (MetaCubeX `v1.9.0-alpha.1` plus
a Firefox 158 parrot and Chrome 155 from refraction-networking/utls). See its
`FORK.md` for the details.

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

## Versions

Every layer sits on an upstream release tag through the layers below it. A
release is tagged `v<upstream>-<layer>.<n>`, for example `v1.19.34-compat.1`,
and `mihomo -v` prints the tag. `<n>` is the revision of the fork on that
upstream release: a change in a layer releases that layer and every layer
above it under the next `<n>`, so the same `<n>` on two layers means the same
stack. `<n>` starts again at 1 on a new upstream release.

Pushing a tag runs `.github/workflows/oviron-release.yml`, which publishes
gzipped `linux-arm64` and `darwin-arm64` binaries named like upstream assets
(`mihomo-linux-arm64-<tag>.gz`) with `SHA256SUMS`. `utls` and `compat` are
built with Go 1.26, `full` with Go 1.27. Only a `compat` release is marked the
latest. `.github/workflows/oviron-test.yml` runs the tests of a layer on every
push to its branch. The upstream workflows are disabled in this repository.

Releases before the layers were tagged `v<upstream>-oviron.<n>`:
`v1.19.34-oviron.2` is `utls`, `v1.19.34-oviron.4` is `compat`, and
`v1.19.34-oviron.3` is `full`, with the commit-by-commit history of that
layer.

## New upstream release

The layers move bottom up, each onto the new place of the one below. Remember
where each branch was, then:

```sh
git fetch upstream --tags
old_utls=$(git rev-parse utls) old_compat=$(git rev-parse compat)
git rebase --onto vNEW vOLD utls
go mod tidy && go build ./...
git rebase --onto utls "$old_utls" compat
git rebase --onto compat "$old_compat" full
# every layer: the three branches are a chain, the build and the tests pass
git merge-base --is-ancestor utls compat && git merge-base --is-ancestor compat full
git push --force-with-lease origin utls compat full
git tag vNEW-utls.1 utls && git tag vNEW-compat.1 compat && git tag vNEW-full.1 full
git push origin vNEW-utls.1 vNEW-compat.1 vNEW-full.1
```

When upstream moves to a utls with Firefox 158 and Chrome 155 of its own, the
`replace` can go and `utls` with it; `compat` and `full` stay until upstream
has what they add.
