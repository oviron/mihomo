package xraytest

import (
	"context"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

const fmHysteriaAuth = "hysteria-auth"

// fmHysteriaInbound is a Hysteria 2 inbound with the given UDP masks.
func fmHysteriaInbound(port int, udpMasks ...obj) obj {
	stream := obj{
		"network":          "hysteria",
		"security":         "tls",
		"tlsSettings":      obj{"alpn": []string{"h3"}, "certificates": tlsSettings()["certificates"]},
		"hysteriaSettings": obj{"version": 2},
	}
	if len(udpMasks) > 0 {
		stream["finalmask"] = obj{"udp": udpMasks}
	}
	return fmInbound("hysteria", port, obj{"version": 2, "clients": []obj{{"auth": fmHysteriaAuth}}}, stream)
}

// fmHysteria is a hysteria2 outbound with the given UDP masks and extra options.
func fmHysteria(t *testing.T, port int, extra obj, udpMasks ...obj) C.Proxy {
	t.Helper()
	mapping := obj{
		"type": "hysteria2", "port": port, "password": fmHysteriaAuth,
		"sni": "example.org", "skip-cert-verify": true,
	}
	if len(udpMasks) > 0 {
		mapping["finalmask"] = obj{"udp": udpMasks}
	}
	for k, v := range extra {
		mapping[k] = v
	}
	return fmProxy(t, mapping)
}

// fmCheckFails expects the proxy to be unable to carry a connection.
func fmCheckFails(t *testing.T, proxy C.ProxyAdapter, tg targets) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := proxy.DialContext(ctx, tcpMetadata(tg.tcp))
	if err != nil {
		return
	}
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(3*time.Second)))
	_, _ = conn.Write([]byte("ping"))
	_, err = conn.Read(make([]byte, 4))
	require.Error(t, err, "the connection must not work")
}

func TestFinalmaskSalamander(t *testing.T) {
	tg := startTargets(t)
	salamander := fmMask("salamander", obj{"password": "obfs-password"})

	t.Run("mask", func(t *testing.T) {
		port := freePort(t)
		startXray(t, fmHysteriaInbound(port, salamander))
		proxy := fmHysteria(t, port, nil, salamander)
		checkTCP(t, proxy, tg)
		checkUDP(t, proxy, tg)
	})

	// The mask and the obfs option of the hysteria2 outbound are the same thing.
	t.Run("hysteria2-obfs-option", func(t *testing.T) {
		port := freePort(t)
		startXray(t, fmHysteriaInbound(port, salamander))
		proxy := fmHysteria(t, port, obj{"obfs": "salamander", "obfs-password": "obfs-password"})
		checkTCP(t, proxy, tg)
	})

	t.Run("wrong-password", func(t *testing.T) {
		port := freePort(t)
		startXray(t, fmHysteriaInbound(port, salamander))
		fmCheckFails(t, fmHysteria(t, port, nil, fmMask("salamander", obj{"password": "another-password"})), tg)
	})

	t.Run("no-mask", func(t *testing.T) {
		port := freePort(t)
		startXray(t, fmHysteriaInbound(port, salamander))
		fmCheckFails(t, fmHysteria(t, port, nil), tg)
	})

	// Two masks: the last one of the list is the one on the wire.
	t.Run("two-masks", func(t *testing.T) {
		port := freePort(t)
		inner := fmMask("salamander", obj{"password": "inner-password"})
		startXray(t, fmHysteriaInbound(port, inner, salamander))
		proxy := fmHysteria(t, port, nil, inner, salamander)
		checkTCP(t, proxy, tg)
		checkUDP(t, proxy, tg)

		port = freePort(t)
		startXray(t, fmHysteriaInbound(port, inner, salamander))
		fmCheckFails(t, fmHysteria(t, port, nil, salamander, inner), tg)
	})
}

func TestFinalmaskGecko(t *testing.T) {
	tg := startTargets(t)
	gecko := fmMask("salamander", obj{"password": "obfs-password", "packetSize": "800-1100"})

	t.Run("mask", func(t *testing.T) {
		port := freePort(t)
		startXray(t, fmHysteriaInbound(port, gecko))
		proxy := fmHysteria(t, port, nil, fmMask("salamander", obj{"password": "obfs-password", "packet-size": "800-1100"}))
		checkTCP(t, proxy, tg)
		checkUDP(t, proxy, tg)
	})

	t.Run("hysteria2-obfs-option", func(t *testing.T) {
		port := freePort(t)
		startXray(t, fmHysteriaInbound(port, gecko))
		proxy := fmHysteria(t, port, obj{
			"obfs": "gecko", "obfs-password": "obfs-password",
			"obfs-min-packet-size": 800, "obfs-max-packet-size": 1100,
		})
		checkTCP(t, proxy, tg)
	})

	t.Run("plain-salamander-client", func(t *testing.T) {
		port := freePort(t)
		startXray(t, fmHysteriaInbound(port, gecko))
		fmCheckFails(t, fmHysteria(t, port, nil, fmMask("salamander", obj{"password": "obfs-password"})), tg)
	})
}
