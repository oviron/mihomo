# oviron/mihomo

Fork of [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) whose only change
is the TLS fingerprint library: `github.com/metacubex/utls` is replaced with
[oviron/utls](https://github.com/oviron/utls) (MetaCubeX `v1.9.0-mod-meta` plus
a Firefox 158 parrot). See its `FORK.md` for the details.

What that means for `client-fingerprint`:

| value | upstream v1.19.33 | this fork |
|---|---|---|
| `chrome` | Chrome 133 | Chrome 133, same ClientHello |
| `firefox` | Firefox 120, no X25519MLKEM768 | Firefox 158, with X25519MLKEM768 |
| `firefox120` | Firefox 120 | Firefox 120, same ClientHello |
| `safari` | Safari 16 | Safari 26.3 |

Firefox 158 is the ClientHello of current Firefox stable in normal browsing mode.
It carries X25519MLKEM768, so Xray REALITY servers from 26.9 on accept it.

## Versions

Branch `oviron` sits on an upstream release tag. A fork release is tagged
`v<upstream>-oviron.<n>` (for example `v1.19.33-oviron.1`), and `mihomo -v` prints
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
