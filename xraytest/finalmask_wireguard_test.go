package xraytest

import (
	"crypto/rand"
	"encoding/base64"
	"net"
	"sync"
	"testing"

	"github.com/metacubex/mihomo/component/generator"
	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

// fmUDPTap is a UDP relay in front of the server that keeps the first
// datagrams of either direction, in the order they came.
type fmUDPTap struct {
	port int

	mu         sync.Mutex
	fromClient [][]byte
	fromServer [][]byte
}

func fmStartUDPTap(t *testing.T, serverPort int) *fmUDPTap {
	t.Helper()
	l, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	upstream, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(loopback(serverPort)))
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close(); _ = upstream.Close() })
	tap := &fmUDPTap{port: l.LocalAddr().(*net.UDPAddr).Port}
	keep := func(list *[][]byte, data []byte) {
		tap.mu.Lock()
		if len(*list) < 64 {
			*list = append(*list, append([]byte(nil), data...))
		}
		tap.mu.Unlock()
	}
	clientCh := make(chan *net.UDPAddr, 1)
	go func() {
		buf := make([]byte, 65535)
		var client *net.UDPAddr
		for {
			n, addr, err := l.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if client == nil {
				client = addr
				clientCh <- addr
			}
			keep(&tap.fromClient, buf[:n])
			_, _ = upstream.Write(buf[:n])
		}
	}()
	go func() {
		client := <-clientCh
		buf := make([]byte, 65535)
		for {
			n, err := upstream.Read(buf)
			if err != nil {
				return
			}
			keep(&tap.fromServer, buf[:n])
			_, _ = l.WriteToUDP(buf[:n], client)
		}
	}()
	return tap
}

// first returns the first n datagrams the client (or the server) sent.
func (tap *fmUDPTap) first(t *testing.T, server bool, n int) [][]byte {
	t.Helper()
	tap.mu.Lock()
	defer tap.mu.Unlock()
	list := tap.fromClient
	if server {
		list = tap.fromServer
	}
	require.GreaterOrEqual(t, len(list), n)
	return list[:n]
}

type fmWireguardPeer struct {
	port                 int
	serverKey, clientKey string // private keys
	serverPub, clientPub string
	psk                  string
}

func fmWireguardKeys(t *testing.T) fmWireguardPeer {
	t.Helper()
	serverKey, err := generator.GenX25519PrivateKey()
	require.NoError(t, err)
	clientKey, err := generator.GenX25519PrivateKey()
	require.NoError(t, err)
	psk := make([]byte, 32)
	_, _ = rand.Read(psk)
	b64 := base64.StdEncoding.EncodeToString
	return fmWireguardPeer{
		serverKey: b64(serverKey.Bytes()), serverPub: b64(serverKey.PublicKey().Bytes()),
		clientKey: b64(clientKey.Bytes()), clientPub: b64(clientKey.PublicKey().Bytes()),
		psk: b64(psk),
	}
}

func (p fmWireguardPeer) inbound(masks []obj) obj {
	var stream obj
	if len(masks) > 0 {
		stream = obj{"finalmask": obj{"udp": masks}}
	}
	return fmInbound("wireguard", p.port, obj{
		"secretKey": p.serverKey,
		"mtu":       1420,
		"peers":     []obj{{"publicKey": p.clientPub, "preSharedKey": p.psk, "allowedIPs": []string{"10.9.0.2/32"}}},
	}, stream)
}

// fmWireguardVia starts a WireGuard inbound of Xray with the server masks and
// returns the mihomo wireguard outbound for it. client is told the port of
// the inbound and names the port to connect to and the client masks.
func fmWireguardVia(t *testing.T, serverMasks []obj, client func(serverPort int) (int, []obj)) (C.Proxy, *xray) {
	t.Helper()
	peer := fmWireguardKeys(t)
	peer.port = freePort(t)
	x := startXray(t, peer.inbound(serverMasks))
	port, clientMasks := client(peer.port)
	mapping := obj{
		"type": "wireguard", "port": port, "udp": true, "mtu": 1420,
		"ip": "10.9.0.2", "private-key": peer.clientKey,
		"public-key": peer.serverPub, "pre-shared-key": peer.psk,
	}
	if len(clientMasks) > 0 {
		mapping["finalmask"] = obj{"udp": clientMasks}
	}
	return fmProxy(t, mapping), x
}

func fmWireguard(t *testing.T, serverMasks, clientMasks []obj) C.Proxy {
	t.Helper()
	proxy, _ := fmWireguardVia(t, serverMasks, func(port int) (int, []obj) { return port, clientMasks })
	return proxy
}

// The messages of WireGuard a tap can tell by their size and first byte.
const (
	fmWGInitiation = 148 // type 1
	fmWGResponse   = 92  // type 2
)

// The UDP masks under WireGuard: a mihomo wireguard outbound against the
// WireGuard inbound of Xray.
func TestFinalmaskWireguard(t *testing.T) {
	// a WireGuard tunnel carries IP packets, which can't go to 127.0.0.1
	tg := startTargets(t).at(hostAddr(t))
	check := func(t *testing.T, proxy C.Proxy) {
		t.Helper()
		checkTCP(t, proxy, tg)
		checkUDP(t, proxy, tg)
	}

	// Three junk datagrams: random letters, which are no WireGuard message
	// type, something of the size of a handshake initiation, and a few bytes.
	noise := fmMask("noise", obj{"noise": []obj{
		{"rand": "40-120", "randRange": "65-90", "delay": "1-3"},
		{"type": "exp", "packet": "<b 0x01000000> <r 144>"},
		{"type": "hex", "packet": "0400000000000000"},
	}})
	// isNoise checks the three datagrams as they are on the wire under a
	// mask that adds extra bytes to each.
	isNoise := func(t *testing.T, datagrams [][]byte, extra int) {
		t.Helper()
		require.GreaterOrEqual(t, len(datagrams[0]), 40+extra)
		require.Less(t, len(datagrams[0]), 120+extra)
		require.Len(t, datagrams[1], 148+extra)
		require.Len(t, datagrams[2], 8+extra)
		if extra == 0 {
			for _, b := range datagrams[0] {
				require.GreaterOrEqual(t, b, byte(65))
				require.LessOrEqual(t, b, byte(90))
			}
			require.Equal(t, []byte{4, 0, 0, 0, 0, 0, 0, 0}, datagrams[2])
		}
	}
	salamander := fmMask("salamander", obj{"password": "obfs-password"})
	header := fmMask("header-custom", obj{
		"client": []obj{{"type": "hex", "packet": "c0ffee"}, {"rand": 5}},
		"server": []obj{{"type": "str", "packet": "wg"}, {"rand": 2, "randRange": "65-90"}},
	})
	sudoku := fmMask("sudoku", obj{"password": "sudoku-password", "paddingMin": 5, "paddingMax": 20})

	// Junk ahead of the handshake, which only the client sends: the server
	// has no mask and drops what is not WireGuard.
	t.Run("noise", func(t *testing.T) {
		var tap *fmUDPTap
		proxy, x := fmWireguardVia(t, nil, func(port int) (int, []obj) {
			tap = fmStartUDPTap(t, port)
			return tap.port, []obj{noise}
		})
		check(t, proxy)
		sent := tap.first(t, false, 4)
		isNoise(t, sent, 0)
		require.Len(t, sent[3], fmWGInitiation, "the handshake comes after the noise")
		require.Equal(t, []byte{1, 0, 0, 0}, sent[3][:4])
		// and the server saw the junk for what it is
		x.waitCount(t, "Received message with unknown type", 1)
		x.waitCount(t, "Received packet with invalid mac1", 1)
	})

	// The server sends its noise too, ahead of its first answer.
	t.Run("noise-both-sides", func(t *testing.T) {
		var tap *fmUDPTap
		proxy, _ := fmWireguardVia(t, []obj{noise}, func(port int) (int, []obj) {
			tap = fmStartUDPTap(t, port)
			return tap.port, []obj{noise}
		})
		check(t, proxy)
		isNoise(t, tap.first(t, false, 3), 0)
		answered := tap.first(t, true, 4)
		isNoise(t, answered, 0)
		require.Len(t, answered[3], fmWGResponse)
		require.Equal(t, []byte{2, 0, 0, 0}, answered[3][:4])
	})

	for _, tc := range []struct {
		name  string
		masks []obj
	}{
		{"salamander", []obj{salamander}},
		{"header-custom", []obj{header}},
		{"sudoku", []obj{sudoku}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			check(t, fmWireguard(t, tc.masks, tc.masks))
		})
	}

	// Three masks: the noise passes through the header and salamander, which
	// add 8 and 8 bytes to every datagram.
	t.Run("noise-header-salamander", func(t *testing.T) {
		masks := []obj{noise, header, salamander}
		var tap *fmUDPTap
		proxy, _ := fmWireguardVia(t, masks, func(port int) (int, []obj) {
			tap = fmStartUDPTap(t, port)
			return tap.port, masks
		})
		check(t, proxy)
		sent := tap.first(t, false, 4)
		isNoise(t, sent, 8+8)
		require.Len(t, sent[3], fmWGInitiation+8+8)
		answered := tap.first(t, true, 4)
		isNoise(t, answered, 4+8)
		require.Len(t, answered[3], fmWGResponse+4+8)
	})

	// The client changes the server port and its own socket, under another
	// mask. WireGuard follows a peer that roams: the server answers to more
	// than one client address.
	t.Run("udphop", func(t *testing.T) {
		var fan *fmFanIn
		proxy, _ := fmWireguardVia(t, []obj{salamander}, func(serverPort int) (int, []obj) {
			fan = fmStartFanIn(t, serverPort, 4)
			return fan.ports[0], []obj{salamander, fmMask("udphop", obj{
				"mode": "intervalLocal,intervalRemote", "interval": 5, "remotePorts": fan.portList(),
			})}
		})
		fmEchoUntil(t, proxy, tg, func() bool {
			_, ports := fan.seen()
			return fan.answered() >= 3 && ports >= 2
		})
		checkUDP(t, proxy, tg)
	})

	// Several peers: the outbound opens one socket for all of them, without
	// naming a server. The masks that wrap a socket work there.
	t.Run("two-peers", func(t *testing.T) {
		ports := freePorts(t, 2)
		used, idle := fmWireguardKeys(t), fmWireguardKeys(t)
		used.port, idle.port = ports[0], ports[1]
		idle.clientKey, idle.clientPub = used.clientKey, used.clientPub // one client, two servers
		startXray(t, used.inbound([]obj{salamander}), idle.inbound([]obj{salamander}))
		mapping := func(masks ...obj) obj {
			return obj{
				"type": "wireguard", "udp": true, "mtu": 1420, "ip": "10.9.0.2", "private-key": used.clientKey,
				"peers": []obj{
					{"server": "127.0.0.1", "port": used.port, "public-key": used.serverPub, "pre-shared-key": used.psk, "allowed-ips": []string{tg.tcp.Addr().String() + "/32"}},
					{"server": "127.0.0.1", "port": idle.port, "public-key": idle.serverPub, "pre-shared-key": idle.psk, "allowed-ips": []string{"198.51.100.0/24"}},
				},
				"finalmask": obj{"udp": masks},
			}
		}
		check(t, fmProxy(t, mapping(salamander)))
		// A mask that picks the server address needs to be told one server.
		fmCheckFails(t, fmProxy(t, mapping(fmMask("udphop", obj{"mode": "intervalLocal"}))), tg)
	})

	// A mask on one side only, or with another password: the handshake
	// reaches the server and is not one for it.
	for _, tc := range []struct {
		name           string
		server, client []obj
	}{
		{"server-mask-only", []obj{salamander}, nil},
		{"client-mask-only", nil, []obj{salamander}},
		{"wrong-password", []obj{salamander}, []obj{fmMask("salamander", obj{"password": "another-password"})}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var tap *fmUDPTap
			proxy, x := fmWireguardVia(t, tc.server, func(port int) (int, []obj) {
				tap = fmStartUDPTap(t, port)
				return tap.port, tc.client
			})
			fmCheckFails(t, proxy, tg)
			tap.first(t, false, 1)
			require.Zero(t, x.count("Received handshake initiation"))
			require.Zero(t, x.count("Sending handshake response"))
		})
	}
}
