package xraytest

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func masqueInbound(port int, alpn ...string) obj {
	return inbound("masque", port, obj{
		"clients": []obj{{"email": "user", "pass": "password"}},
		"address": []string{"10.9.0.1/24", "fd09::1/64"},
	}, obj{
		"network": "masque", "security": "tls",
		"tlsSettings": obj{"alpn": alpn, "certificates": tlsSettings()["certificates"]},
	})
}

// TestMasque is the CONNECT-IP tunnel of an Xray MASQUE inbound over HTTP/3:
// Basic authentication, addresses assigned by the server.
func TestMasque(t *testing.T) {
	tg := startTargets(t).at(hostAddr(t)) // an IP tunnel does not reach 127.0.0.1
	port := freePort(t)
	x := startXray(t, masqueInbound(port, "h3"))
	mapping := func(pass string) obj {
		return obj{
			"type": "masque", "port": port, "udp": true,
			"user": "user", "pass": pass,
			"sni": "example.org", "skip-cert-verify": true,
		}
	}

	proxy := newProxy(t, mapping("password"))
	checkTCP(t, proxy, tg)
	checkTLS(t, proxy, tg)
	checkUDP(t, proxy, tg)
	checkUDPTwoTargets(t, proxy, tg)
	x.waitCount(t, "MASQUE: tunnel from", 1)
	require.Equal(t, 1, x.count("MASQUE: tunnel from"), "one tunnel carries everything")
	require.Contains(t, x.log.String(), "assigned [10.9.0.")

	t.Run("wrong-password", func(t *testing.T) {
		rejected := newProxy(t, mapping("wrong"))
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := rejected.DialContext(ctx, tcpMetadata(tg.tcp))
		if err == nil {
			_ = conn.Close()
		}
		require.ErrorContains(t, err, "401")
		x.waitCount(t, "MASQUE: authentication failed", 1)
	})

	t.Run("reconnect", func(t *testing.T) {
		// the server gives every connection new addresses
		again := newProxy(t, mapping("password"))
		checkTCP(t, again, tg)
		checkUDP(t, again, tg)
		x.waitCount(t, "MASQUE: tunnel from", 2)
		checkTCP(t, proxy, tg) // the first tunnel is not disturbed
	})

	t.Run("server-restart", func(t *testing.T) {
		// the same outbound sets the tunnel up again, on the new addresses
		x.stop()
		restarted := startXray(t, masqueInbound(port, "h3"))
		require.Eventually(t, func() bool {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			conn, err := proxy.DialContext(ctx, tcpMetadata(tg.tcp))
			if err != nil {
				return false
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			if _, err = conn.Write([]byte("ping")); err != nil {
				return false
			}
			_, err = io.ReadFull(conn, make([]byte, 4))
			return err == nil
		}, 60*time.Second, time.Second)
		checkTCP(t, proxy, tg)
		checkUDP(t, proxy, tg)
		require.Equal(t, 1, restarted.count("MASQUE: tunnel from"))
	})
}
