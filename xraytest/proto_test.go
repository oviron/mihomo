package xraytest

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/component/generator"
	C "github.com/metacubex/mihomo/constant"
	vlessenc "github.com/metacubex/mihomo/transport/vless/encryption"

	"github.com/stretchr/testify/require"
)

func newProxy(t *testing.T, mapping obj) C.Proxy {
	t.Helper()
	mapping["name"] = "xray"
	mapping["server"] = "127.0.0.1"
	proxy, err := adapter.ParseProxy(mapping)
	require.NoError(t, err)
	t.Cleanup(func() { _ = proxy.Close() })
	return proxy
}

func inbound(protocol string, port int, settings obj, stream obj) obj {
	in := obj{"listen": "127.0.0.1", "port": port, "protocol": protocol, "settings": settings}
	if stream != nil {
		in["streamSettings"] = stream
	}
	return in
}

func tlsStream() obj {
	return obj{"network": "raw", "security": "tls", "tlsSettings": tlsSettings()}
}

func randomKey(t *testing.T, size int) string {
	t.Helper()
	key := make([]byte, size)
	_, err := rand.Read(key)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(key)
}

func TestVless(t *testing.T) {
	tg := startTargets(t)
	port := freePort(t)
	x := startXray(t, inbound("vless", port, obj{
		"clients":    []obj{{"id": userUUID}},
		"decryption": "none",
	}, nil))
	proxy := newProxy(t, obj{"type": "vless", "port": port, "uuid": userUUID, "udp": true})
	checkTCP(t, proxy, tg)
	checkUDP(t, proxy, tg)
	checkUDPFullCone(t, proxy, tg)
	checkXUDPGlobalID(t, x, proxy, tg)
}

// vlessencPair returns the matching "decryption" and "encryption" values.
func vlessencPair(t *testing.T, mode, serverSeconds, clientRTT, padding string, keys ...string) (decryption, encryption string) {
	t.Helper()
	decryption = "mlkem768x25519plus." + mode + "." + serverSeconds
	encryption = "mlkem768x25519plus." + mode + "." + clientRTT
	if padding != "" {
		decryption += "." + padding
		encryption += "." + padding
	}
	for _, key := range keys {
		var server, client string
		var err error
		switch key {
		case "x25519":
			server, client, _, err = vlessenc.GenX25519("")
		case "mlkem768":
			server, client, _, err = vlessenc.GenMLKEM768("")
		default:
			t.Fatalf("unknown key type %s", key)
		}
		require.NoError(t, err)
		decryption += "." + server
		encryption += "." + client
	}
	return
}

func TestVlessEncryption(t *testing.T) {
	tg := startTargets(t)
	cases := []struct {
		name          string
		mode          string
		serverSeconds string
		clientRTT     string
		padding       string
		keys          []string
	}{
		{"native-1rtt-x25519", "native", "0s", "1rtt", "", []string{"x25519"}},
		{"native-0rtt-x25519", "native", "600s", "0rtt", "", []string{"x25519"}},
		{"xorpub-0rtt-x25519", "xorpub", "600s", "0rtt", "", []string{"x25519"}},
		{"random-0rtt-x25519", "random", "600s", "0rtt", "", []string{"x25519"}},
		{"native-0rtt-mlkem768", "native", "600s", "0rtt", "", []string{"mlkem768"}},
		{"random-1rtt-mlkem768", "random", "0s", "1rtt", "", []string{"mlkem768"}},
		{"random-0rtt-range-x25519-mlkem768", "random", "300-600s", "0rtt", "", []string{"x25519", "mlkem768"}},
		{"native-0rtt-padding", "native", "600s", "0rtt", "100-111-1111.75-0-111.50-0-3333", []string{"x25519"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			decryption, encryption := vlessencPair(t, tc.mode, tc.serverSeconds, tc.clientRTT, tc.padding, tc.keys...)
			port := freePort(t)
			startXray(t, inbound("vless", port, obj{
				"clients":    []obj{{"id": userUUID}},
				"decryption": decryption,
			}, nil))
			proxy := newProxy(t, obj{"type": "vless", "port": port, "uuid": userUUID, "udp": true, "encryption": encryption})
			checkTCP(t, proxy, tg)
			checkTLS(t, proxy, tg) // a second connection, 0-RTT where enabled
			checkUDP(t, proxy, tg)
			checkUDPFullCone(t, proxy, tg)
		})
	}
}

func TestVlessVision(t *testing.T) {
	tg := startTargets(t)
	const flow = "xtls-rprx-vision"

	t.Run("tls", func(t *testing.T) {
		port := freePort(t)
		x := startXray(t, inbound("vless", port, obj{
			"clients":    []obj{{"id": userUUID, "flow": flow}},
			"decryption": "none",
		}, tlsStream()))
		proxy := newProxy(t, obj{
			"type": "vless", "port": port, "uuid": userUUID, "udp": true, "flow": flow,
			"tls": true, "skip-cert-verify": true, "servername": "example.org",
		})
		checkTCP(t, proxy, tg)
		checkTLS(t, proxy, tg)
		checkVisionDirect(t, x)
		checkUDP(t, proxy, tg)
		checkUDPFullCone(t, proxy, tg)
		checkXUDPGlobalID(t, x, proxy, tg)
	})

	t.Run("tls-testseed", func(t *testing.T) {
		port := freePort(t)
		x := startXray(t, inbound("vless", port, obj{
			"clients":    []obj{{"id": userUUID, "flow": flow}},
			"decryption": "none",
			"testseed":   []int{2000, 1500, 2000, 1000},
		}, tlsStream()))
		proxy := newProxy(t, obj{
			"type": "vless", "port": port, "uuid": userUUID, "udp": true, "flow": flow,
			"tls": true, "skip-cert-verify": true, "servername": "example.org",
		})
		checkTCP(t, proxy, tg)
		checkTLS(t, proxy, tg)
		checkVisionDirect(t, x)
		checkUDP(t, proxy, tg)
		// the server pads short blocks to 2000-3500 bytes, far above the default 900-1400
		longest := 0
		for _, block := range visionServerBlocks(x) {
			if block.padding > longest {
				longest = block.padding
			}
		}
		require.Greater(t, longest, 1500, "server testseed must be in effect")
	})

	for _, mode := range []string{"native", "xorpub", "random"} {
		t.Run("encryption-"+mode, func(t *testing.T) {
			decryption, encryption := vlessencPair(t, mode, "600s", "0rtt", "", "mlkem768")
			port := freePort(t)
			x := startXray(t, inbound("vless", port, obj{
				"clients":    []obj{{"id": userUUID, "flow": flow}},
				"decryption": decryption,
			}, nil))
			proxy := newProxy(t, obj{
				"type": "vless", "port": port, "uuid": userUUID, "udp": true, "flow": flow,
				"encryption": encryption,
			})
			checkTCP(t, proxy, tg)
			checkTLS(t, proxy, tg)
			checkVisionDirect(t, x)
			checkUDP(t, proxy, tg)
			checkUDPFullCone(t, proxy, tg)
		})
	}
}

// visionBlock is one XTLS Vision padding block from the Xray debug log.
type visionBlock struct {
	content, padding, command int
}

var (
	visionClientBlock = regexp.MustCompile(`Xtls Unpadding new block, content (\d+) padding (\d+) command (\d+)`)
	visionServerBlock = regexp.MustCompile(`XtlsPadding (\d+) (\d+) (\d+)`)
)

func visionBlocks(x *xray, re *regexp.Regexp) (blocks []visionBlock) {
	for _, m := range re.FindAllStringSubmatch(x.log.String(), -1) {
		var b visionBlock
		b.content, _ = strconv.Atoi(m[1])
		b.padding, _ = strconv.Atoi(m[2])
		b.command, _ = strconv.Atoi(m[3])
		blocks = append(blocks, b)
	}
	return
}

// visionClientBlocks are the blocks the client wrote, as the server parsed them.
func visionClientBlocks(x *xray) []visionBlock { return visionBlocks(x, visionClientBlock) }

// visionServerBlocks are the blocks the server wrote.
func visionServerBlocks(x *xray) []visionBlock { return visionBlocks(x, visionServerBlock) }

// checkVisionDirect expects both sides to have left the padding phase with the
// direct copy command, which they only do for an inner TLS 1.3 session.
func checkVisionDirect(t *testing.T, x *xray) {
	t.Helper()
	const direct = 2
	hasDirect := func(blocks []visionBlock) bool {
		for _, b := range blocks {
			if b.command == direct {
				return true
			}
		}
		return false
	}
	x.waitFor(t, "client must switch to direct copy", func() bool { return hasDirect(visionClientBlocks(x)) })
	x.waitFor(t, "server must switch to direct copy", func() bool { return hasDirect(visionServerBlocks(x)) })
}

// TestVlessRoute checks that bytes 6-7 of the UUID sent by the client reach
// the server's "vlessRoute" routing condition.
func TestVlessRoute(t *testing.T) {
	tg := startTargets(t)
	port := freePort(t)
	x := startXrayConfig(t, obj{
		"log": obj{"loglevel": "debug"},
		"inbounds": []obj{inbound("vless", port, obj{
			"clients":    []obj{{"id": userUUID}},
			"decryption": "none",
		}, nil)},
		"outbounds": []obj{
			{"protocol": "blackhole", "tag": "block"},
			freedom("direct"),
		},
		"routing": obj{"rules": []obj{{"vlessRoute": "3000", "outboundTag": "direct"}}},
	})

	routed := newProxy(t, obj{"type": "vless", "port": port, "uuid": "b831381d-6324-0bb8-ad4f-8cda48b30811"})
	checkTCP(t, routed, tg)
	require.Equal(t, 1, x.count("taking detour [direct]"), "the routed UUID must match the vlessRoute rule")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	blocked := newProxy(t, obj{"type": "vless", "port": port, "uuid": userUUID})
	conn, err := blocked.DialContext(ctx, tcpMetadata(tg.tcp))
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(3*time.Second)))
	_, err = conn.Write([]byte("ping"))
	require.NoError(t, err)
	_, err = conn.Read(make([]byte, 4))
	require.Error(t, err, "the default UUID must fall to the blackhole outbound")
	x.waitCount(t, "[block]", 1)
	require.Equal(t, 1, x.count("taking detour [direct]"))
}

func TestVmess(t *testing.T) {
	tg := startTargets(t)
	port := freePort(t)
	x := startXray(t, inbound("vmess", port, obj{"clients": []obj{{"id": userUUID}}}, nil))

	for _, cipher := range []string{"auto", "aes-128-gcm", "chacha20-poly1305"} {
		t.Run(cipher, func(t *testing.T) {
			proxy := newProxy(t, obj{"type": "vmess", "port": port, "uuid": userUUID, "alterId": 0, "cipher": cipher, "udp": true})
			checkTCP(t, proxy, tg)
			checkUDP(t, proxy, tg)
		})
	}
	t.Run("authenticated-length-global-padding", func(t *testing.T) {
		proxy := newProxy(t, obj{
			"type": "vmess", "port": port, "uuid": userUUID, "alterId": 0, "cipher": "auto", "udp": true,
			"authenticated-length": true, "global-padding": true,
		})
		checkTCP(t, proxy, tg)
		checkUDP(t, proxy, tg)
	})
	t.Run("xudp", func(t *testing.T) {
		proxy := newProxy(t, obj{
			"type": "vmess", "port": port, "uuid": userUUID, "alterId": 0, "cipher": "auto", "udp": true,
			"packet-encoding": "xudp",
		})
		checkUDP(t, proxy, tg)
		checkUDPFullCone(t, proxy, tg)
		checkXUDPGlobalID(t, x, proxy, tg)
	})
}

func TestTrojan(t *testing.T) {
	tg := startTargets(t)
	port := freePort(t)
	startXray(t, inbound("trojan", port, obj{"clients": []obj{{"password": "password"}}}, tlsStream()))
	proxy := newProxy(t, obj{
		"type": "trojan", "port": port, "password": "password", "udp": true,
		"skip-cert-verify": true, "sni": "example.org",
	})
	checkTCP(t, proxy, tg)
	checkUDP(t, proxy, tg)
	checkUDPFullCone(t, proxy, tg)
}

func TestShadowsocks(t *testing.T) {
	tg := startTargets(t)
	cases := []struct {
		method   string
		password string
	}{
		{"aes-128-gcm", "password"},
		{"aes-256-gcm", "password"},
		{"chacha20-ietf-poly1305", "password"},
		{"xchacha20-ietf-poly1305", "password"},
		{"2022-blake3-aes-128-gcm", randomKey(t, 16)},
		{"2022-blake3-aes-256-gcm", randomKey(t, 32)},
		{"2022-blake3-chacha20-poly1305", randomKey(t, 32)},
	}
	for _, tc := range cases {
		t.Run(tc.method, func(t *testing.T) {
			port := freePort(t)
			startXray(t, inbound("shadowsocks", port, obj{
				"method": tc.method, "password": tc.password, "network": "tcp,udp",
			}, nil))
			proxy := newProxy(t, obj{"type": "ss", "port": port, "cipher": tc.method, "password": tc.password, "udp": true})
			checkTCP(t, proxy, tg)
			checkUDP(t, proxy, tg)
			checkUDPFullCone(t, proxy, tg)
		})
	}

	for _, size := range []int{16, 32} {
		method := map[int]string{16: "2022-blake3-aes-128-gcm", 32: "2022-blake3-aes-256-gcm"}[size]
		t.Run(method+"-multi-user", func(t *testing.T) {
			serverKey, userKey := randomKey(t, size), randomKey(t, size)
			port := freePort(t)
			startXray(t, inbound("shadowsocks", port, obj{
				"method": method, "password": serverKey, "network": "tcp,udp",
				"clients": []obj{{"password": randomKey(t, size), "email": "other"}, {"password": userKey, "email": "user"}},
			}, nil))
			proxy := newProxy(t, obj{"type": "ss", "port": port, "cipher": method, "password": serverKey + ":" + userKey, "udp": true})
			checkTCP(t, proxy, tg)
			checkUDP(t, proxy, tg)
			checkUDPFullCone(t, proxy, tg)
		})
	}
}

// TestShadowsocks2022Relay goes through an Xray relay inbound to a terminal
// Xray inbound, the client holding the keys of both hops.
func TestShadowsocks2022Relay(t *testing.T) {
	tg := startTargets(t)
	const method = "2022-blake3-aes-128-gcm"
	relayKey, serverKey := randomKey(t, 16), randomKey(t, 16)
	ports := freePorts(t, 2)
	relayPort, serverPort := ports[0], ports[1]
	startXray(t,
		inbound("shadowsocks", relayPort, obj{
			"method": method, "password": relayKey, "network": "tcp,udp",
			"clients": []obj{{"password": serverKey, "email": "server", "address": "127.0.0.1", "port": serverPort}},
		}, nil),
		inbound("shadowsocks", serverPort, obj{
			"method": method, "password": serverKey, "network": "tcp,udp",
		}, nil),
	)
	proxy := newProxy(t, obj{"type": "ss", "port": relayPort, "cipher": method, "password": relayKey + ":" + serverKey, "udp": true})
	checkTCP(t, proxy, tg)
	checkUDP(t, proxy, tg)
	checkUDPFullCone(t, proxy, tg)
}

func TestHysteria2(t *testing.T) {
	tg := startTargets(t)
	port := freePort(t)
	stream := obj{
		"network": "hysteria", "security": "tls",
		"tlsSettings":      obj{"alpn": []string{"h3"}, "certificates": tlsSettings()["certificates"]},
		"hysteriaSettings": obj{"version": 2},
	}
	startXray(t, inbound("hysteria", port, obj{
		"version": 2,
		"clients": []obj{{"auth": "password", "email": "user"}},
	}, stream))
	proxy := newProxy(t, obj{
		"type": "hysteria2", "port": port, "password": "password", "udp": true,
		"skip-cert-verify": true, "sni": "example.org",
	})
	checkTCP(t, proxy, tg)
	checkUDP(t, proxy, tg)
	checkUDPFullCone(t, proxy, tg)

	// larger than a QUIC datagram: goes through hysteria's UDP fragmentation
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pc, err := proxy.ListenPacketContext(ctx, udpMetadata(tg.udp))
	require.NoError(t, err)
	defer pc.Close()
	udpRoundTrip(t, pc, tg.udp, 4000)
}

func TestSocks5(t *testing.T) {
	tg := startTargets(t)
	port := freePort(t)
	startXray(t, inbound("socks", port, obj{
		"auth": "password", "accounts": []obj{{"user": "user", "pass": "password"}},
		"udp": true, "ip": "127.0.0.1",
	}, nil))
	proxy := newProxy(t, obj{"type": "socks5", "port": port, "username": "user", "password": "password", "udp": true})
	checkTCP(t, proxy, tg)
	checkUDP(t, proxy, tg)
	checkUDPFullCone(t, proxy, tg)
}

func TestHTTP(t *testing.T) {
	tg := startTargets(t)
	port := freePort(t)
	startXray(t, inbound("http", port, obj{"accounts": []obj{{"user": "user", "pass": "password"}}}, nil))
	proxy := newProxy(t, obj{"type": "http", "port": port, "username": "user", "password": "password"})
	checkTCP(t, proxy, tg)
}

// TestMixed uses both protocols of the SOCKS inbound: SOCKS5 and HTTP CONNECT.
func TestMixed(t *testing.T) {
	tg := startTargets(t)
	port := freePort(t)
	startXray(t, inbound("mixed", port, obj{
		"auth": "password", "accounts": []obj{{"user": "user", "pass": "password"}},
		"udp": true, "ip": "127.0.0.1",
	}, nil))
	socks := newProxy(t, obj{"type": "socks5", "port": port, "username": "user", "password": "password", "udp": true})
	checkTCP(t, socks, tg)
	checkUDP(t, socks, tg)
	http := newProxy(t, obj{"type": "http", "port": port, "username": "user", "password": "password"})
	checkTCP(t, http, tg)
}

func TestWireGuard(t *testing.T) {
	tg := startTargets(t).at(hostAddr(t))
	serverKey, err := generator.GenX25519PrivateKey()
	require.NoError(t, err)
	clientKey, err := generator.GenX25519PrivateKey()
	require.NoError(t, err)
	b64 := base64.StdEncoding.EncodeToString
	psk := randomKey(t, 32)

	port := freePort(t)
	startXray(t, inbound("wireguard", port, obj{
		"secretKey": b64(serverKey.Bytes()),
		"mtu":       1420,
		"peers": []obj{{
			"publicKey":    b64(clientKey.PublicKey().Bytes()),
			"preSharedKey": psk,
			"allowedIPs":   []string{"10.9.0.2/32"},
		}},
	}, nil))
	proxy := newProxy(t, obj{
		"type": "wireguard", "port": port, "udp": true, "mtu": 1420,
		"ip":             "10.9.0.2",
		"private-key":    b64(clientKey.Bytes()),
		"public-key":     b64(serverKey.PublicKey().Bytes()),
		"pre-shared-key": psk,
	})
	checkTCP(t, proxy, tg)
	checkUDP(t, proxy, tg)
	// one WireGuard peer is an IP host, the server opens a socket per flow
	checkUDPTwoTargets(t, proxy, tg)
}
