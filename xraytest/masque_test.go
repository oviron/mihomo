package xraytest

import (
	"context"
	"io"
	"net/netip"
	"os/exec"
	"strings"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

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

// echKeys asks Xray for an ECH key pair: the config list for the client and
// the keys for the server.
func echKeys(t *testing.T) (configList, serverKeys string) {
	t.Helper()
	out, err := exec.Command(xrayBin(t), "tls", "ech", "--serverName", "public.example").CombinedOutput()
	require.NoError(t, err, string(out))
	lines := strings.Split(string(out), "\n")
	for i, line := range lines {
		if i+1 >= len(lines) {
			break
		}
		switch {
		case strings.HasPrefix(line, "ECH config list"):
			configList = strings.TrimSpace(lines[i+1])
		case strings.HasPrefix(line, "ECH server keys"):
			serverKeys = strings.TrimSpace(lines[i+1])
		}
	}
	require.NotEmpty(t, configList, string(out))
	require.NotEmpty(t, serverKeys, string(out))
	return
}

// TestMasqueTLS covers the TLS options of the tunnel on both transports: the
// certificate pin, ECH, and remote DNS through the tunnel.
func TestMasqueTLS(t *testing.T) {
	tg := startTargets(t).at(hostAddr(t))
	configList, serverKeys := echKeys(t)
	for _, network := range []string{"h3", "h2"} {
		t.Run(network, func(t *testing.T) {
			port := freePort(t)
			in := masqueInbound(port, network)
			in["streamSettings"].(obj)["tlsSettings"].(obj)["echServerKeys"] = serverKeys
			startXray(t, in)
			mapping := func(extra obj) obj {
				m := obj{
					"type": "masque", "port": port, "udp": true, "network": network,
					"user": "user", "pass": "password", "sni": "example.org",
				}
				for k, v := range extra {
					m[k] = v
				}
				return m
			}
			dial := func(proxy C.Proxy) error {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				conn, err := proxy.DialContext(ctx, tcpMetadata(tg.tcp))
				if err == nil {
					_ = conn.Close()
				}
				return err
			}

			t.Run("fingerprint", func(t *testing.T) {
				// the test certificate is self-signed: only the pin makes it trusted
				checkTCP(t, newProxy(t, mapping(obj{"fingerprint": tlsFingerprint})), tg)
				require.Error(t, dial(newProxy(t, mapping(nil))), "an unknown certificate must be refused")
				wrong := strings.Repeat("00", 32)
				require.Error(t, dial(newProxy(t, mapping(obj{"fingerprint": wrong}))), "another certificate must be refused")
			})

			t.Run("ech", func(t *testing.T) {
				ech := obj{"enable": true, "config": configList}
				proxy := newProxy(t, mapping(obj{"skip-cert-verify": true, "ech-opts": ech}))
				checkTCP(t, proxy, tg)
				checkUDP(t, proxy, tg)
			})

			t.Run("remote-dns", func(t *testing.T) {
				// the name is resolved by a DNS server reached through the tunnel
				dns := startDNS(t, tg.tcp.Addr())
				proxy := newProxy(t, mapping(obj{
					"skip-cert-verify": true, "remote-dns-resolve": true,
					"dns": []string{"udp://" + netip.AddrPortFrom(tg.tcp.Addr(), dns.addr.Port()).String()},
				}))
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				metadata := tcpMetadata(tg.tcp)
				metadata.Host, metadata.DstIP = "target.example", netip.Addr{}
				conn, err := proxy.DialContext(ctx, metadata)
				require.NoError(t, err)
				defer conn.Close()
				echoRoundTrip(t, conn, 1000)
				require.Positive(t, dns.queries.Load())
			})
		})
	}
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

// TestMasqueH2 is the same tunnel over HTTP/2: TCP and TLS all the way, for
// networks where UDP does not get through.
func TestMasqueH2(t *testing.T) {
	tg := startTargets(t).at(hostAddr(t))
	port := freePort(t)
	x := startXray(t, masqueInbound(port, "h2"))
	mapping := func(pass string) obj {
		return obj{
			"type": "masque", "port": port, "udp": true, "network": "h2",
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
	require.Contains(t, x.log.String(), "listening TCP for MASQUE over HTTP/2")
	require.NotContains(t, x.log.String(), "listening UDP for MASQUE")

	t.Run("client-fingerprint", func(t *testing.T) {
		for _, fingerprint := range []string{"chrome", "firefox", "safari"} {
			m := mapping("password")
			m["client-fingerprint"] = fingerprint
			checkTCP(t, newProxy(t, m), tg)
		}
	})

	t.Run("wrong-password", func(t *testing.T) {
		rejected := newProxy(t, mapping("wrong"))
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := rejected.DialContext(ctx, tcpMetadata(tg.tcp))
		if err == nil {
			_ = conn.Close()
		}
		require.ErrorContains(t, err, "401")
	})

	t.Run("server-restart", func(t *testing.T) {
		x.stop()
		restarted := startXray(t, masqueInbound(port, "h2"))
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
