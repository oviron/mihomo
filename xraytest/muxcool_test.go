package xraytest

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

// muxCase is a proxy whose connections are multiplexed with Mux.Cool.
type muxCase struct {
	name    string
	inbound func(port int) obj
	proxy   obj
}

func muxCases(t *testing.T) []muxCase {
	ssKey := randomKey(t, 16)
	return []muxCase{
		{"vless", func(port int) obj {
			return inbound("vless", port, obj{"clients": []obj{{"id": userUUID}}, "decryption": "none"}, nil)
		}, obj{"type": "vless", "uuid": userUUID, "udp": true}},
		{"vmess", func(port int) obj {
			return inbound("vmess", port, obj{"clients": []obj{{"id": userUUID}}}, nil)
		}, obj{"type": "vmess", "uuid": userUUID, "alterId": 0, "cipher": "auto", "udp": true}},
		{"trojan", func(port int) obj {
			return inbound("trojan", port, obj{"clients": []obj{{"password": "password"}}}, tlsStream())
		}, obj{"type": "trojan", "password": "password", "udp": true, "skip-cert-verify": true, "sni": "example.org"}},
		{"shadowsocks-2022", func(port int) obj {
			return inbound("shadowsocks", port, obj{"method": "2022-blake3-aes-128-gcm", "password": ssKey, "network": "tcp,udp"}, nil)
		}, obj{"type": "ss", "cipher": "2022-blake3-aes-128-gcm", "password": ssKey, "udp": true}},
	}
}

func (mc muxCase) start(t *testing.T, mux obj) (*xray, C.Proxy) {
	t.Helper()
	port := freePort(t)
	x := startXray(t, mc.inbound(port))
	mapping := obj{"port": port, "mux": mux}
	for k, v := range mc.proxy {
		mapping[k] = v
	}
	return x, newProxy(t, mapping)
}

// carriers is the number of Mux.Cool connections the server has accepted.
func carriers(x *xray) int {
	return x.count("tcp:v1.mux.cool:9527")
}

// parallel runs n copies of check at once.
func parallel(t *testing.T, n int, check func(t *testing.T)) {
	t.Helper()
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			check(t)
		}()
	}
	wg.Wait()
}

func TestMuxCool(t *testing.T) {
	tg := startTargets(t)
	for _, mc := range muxCases(t) {
		t.Run(mc.name, func(t *testing.T) {
			x, proxy := mc.start(t, obj{"enabled": true})
			checkTCP(t, proxy, tg)
			checkTLS(t, proxy, tg)
			checkUDP(t, proxy, tg)
			checkUDPFullCone(t, proxy, tg)
			checkXUDPGlobalID(t, x, proxy, tg)
			// streams and packets at once, all on the connection opened first
			parallel(t, 8, func(t *testing.T) {
				checkTCP(t, proxy, tg)
				checkUDP(t, proxy, tg)
			})
			require.Equal(t, 1, carriers(x), "everything must share one Mux.Cool connection")
		})
	}
}

// TestMuxCoolConcurrency checks the session limit of one connection and the
// separate connections for UDP.
func TestMuxCoolConcurrency(t *testing.T) {
	tg := startTargets(t)
	mc := muxCases(t)[0]

	t.Run("concurrency", func(t *testing.T) {
		x, proxy := mc.start(t, obj{"enabled": true, "concurrency": 2})
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		for i := 0; i < 5; i++ { // five streams held open: 2 + 2 + 1
			conn, err := proxy.DialContext(ctx, tcpMetadata(tg.tcp))
			require.NoError(t, err)
			defer conn.Close()
			echoRoundTrip(t, conn, 100)
		}
		x.waitCount(t, "tcp:v1.mux.cool:9527", 3)
		require.Equal(t, 3, carriers(x))
	})

	t.Run("xudp-concurrency", func(t *testing.T) {
		x, proxy := mc.start(t, obj{"enabled": true, "xudp-concurrency": 16})
		checkTCP(t, proxy, tg)
		checkUDP(t, proxy, tg)
		checkUDPFullCone(t, proxy, tg)
		x.waitCount(t, "tcp:v1.mux.cool:9527", 2)
		require.Equal(t, 2, carriers(x), "UDP must get a connection of its own")
	})

	t.Run("udp-only", func(t *testing.T) {
		x, proxy := mc.start(t, obj{"enabled": true, "concurrency": -1, "xudp-concurrency": 16})
		checkTCP(t, proxy, tg) // straight through the proxy
		require.Equal(t, 0, carriers(x))
		checkUDP(t, proxy, tg)
		checkUDPFullCone(t, proxy, tg)
		x.waitCount(t, "tcp:v1.mux.cool:9527", 1)
		require.Equal(t, 1, carriers(x), "UDP must go through Mux.Cool")
	})

	t.Run("udp443", func(t *testing.T) {
		_, proxy := mc.start(t, obj{"enabled": true})
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		quic := udpMetadata(tg.udp)
		quic.DstPort = 443
		pc, err := proxy.ListenPacketContext(ctx, quic)
		if err == nil {
			_ = pc.Close()
		}
		require.ErrorContains(t, err, "UDP/443")
	})
}

// TestMuxCoolSessionEnd checks that a session the server could not connect
// ends without taking the connection or the other sessions with it.
func TestMuxCoolSessionEnd(t *testing.T) {
	tg := startTargets(t)
	x, proxy := muxCases(t)[0].start(t, obj{"enabled": true})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	alive, err := proxy.DialContext(ctx, tcpMetadata(tg.tcp))
	require.NoError(t, err)
	defer alive.Close()
	echoRoundTrip(t, alive, 100)

	refused := tcpMetadata(tg.tcp)
	refused.DstPort = uint16(freePort(t)) // nothing listens there
	conn, err := proxy.DialContext(ctx, refused)
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))
	_, err = conn.Write([]byte("ping"))
	require.NoError(t, err)
	_, err = conn.Read(make([]byte, 4))
	require.Error(t, err)
	require.NotErrorIs(t, err, os.ErrDeadlineExceeded, "the server must end the session")

	echoRoundTrip(t, alive, 1<<20)
	checkTCP(t, proxy, tg)
	require.Equal(t, 1, carriers(x))
}

// TestMuxCoolVision: an XTLS Vision account takes no TCP in Mux.Cool, so the
// option leaves its connections alone and applies the UDP/443 rule only.
func TestMuxCoolVision(t *testing.T) {
	tg := startTargets(t)
	const flow = "xtls-rprx-vision"
	port := freePort(t)
	x := startXray(t, inbound("vless", port, obj{
		"clients":    []obj{{"id": userUUID, "flow": flow}},
		"decryption": "none",
	}, tlsStream()))
	proxy := newProxy(t, obj{
		"type": "vless", "port": port, "uuid": userUUID, "udp": true, "flow": flow,
		"tls": true, "skip-cert-verify": true, "servername": "example.org",
		"mux": obj{"enabled": true, "xudp-proxy-udp443": "skip"},
	})
	checkTLS(t, proxy, tg)
	checkVisionDirect(t, x)
	checkTCP(t, proxy, tg)
	checkUDP(t, proxy, tg)
	checkUDPFullCone(t, proxy, tg)
	require.Equal(t, 0, carriers(x))
}
