package xraytest

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

// fmFanIn stands for a server reachable on several ports: it listens on them
// and relays to one server port, with an upstream socket per client address,
// so the server sees a client that changes its socket as a new source.
type fmFanIn struct {
	ports []int

	mu      sync.Mutex
	clients map[string]*net.UDPConn // client address -> upstream socket
	hits    map[int]int             // port -> packets
}

func fmStartFanIn(t *testing.T, serverPort, n int) *fmFanIn {
	t.Helper()
	fan := &fmFanIn{clients: map[string]*net.UDPConn{}, hits: map[int]int{}}
	server := net.UDPAddrFromAddrPort(loopback(serverPort))
	for i := 0; i < n; i++ {
		l, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		require.NoError(t, err)
		t.Cleanup(func() { _ = l.Close() })
		port := l.LocalAddr().(*net.UDPAddr).Port
		fan.ports = append(fan.ports, port)
		go func() {
			buf := make([]byte, 65535)
			for {
				n, client, err := l.ReadFromUDP(buf)
				if err != nil {
					return
				}
				fan.mu.Lock()
				fan.hits[port]++
				upstream := fan.clients[client.String()]
				if upstream == nil {
					upstream, err = net.DialUDP("udp", nil, server)
					if err != nil {
						fan.mu.Unlock()
						continue
					}
					fan.clients[client.String()] = upstream
					t.Cleanup(func() { _ = upstream.Close() })
					// answers go back from the port the client spoke to first
					go func() {
						buf := make([]byte, 65535)
						for {
							n, err := upstream.Read(buf)
							if err != nil {
								return
							}
							_, _ = l.WriteToUDP(buf[:n], client)
						}
					}()
				}
				fan.mu.Unlock()
				_, _ = upstream.Write(buf[:n])
			}
		}()
	}
	return fan
}

func (fan *fmFanIn) portList() string {
	list := make([]string, len(fan.ports))
	for i, port := range fan.ports {
		list[i] = strconv.Itoa(port)
	}
	return strings.Join(list, ",")
}

// seen returns how many client addresses and how many ports were used.
func (fan *fmFanIn) seen() (clients, ports int) {
	fan.mu.Lock()
	defer fan.mu.Unlock()
	return len(fan.clients), len(fan.hits)
}

// fmEchoUntil keeps one proxied connection busy until done reports true: the
// connection has to survive the hops made meanwhile.
func fmEchoUntil(t *testing.T, proxy C.ProxyAdapter, tg targets, done func() bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := proxy.DialContext(ctx, tcpMetadata(tg.tcp))
	require.NoError(t, err)
	defer conn.Close()
	deadline := time.Now().Add(60 * time.Second)
	for i := 0; !done(); i++ {
		if time.Now().After(deadline) {
			t.Fatal("no hop was seen within a minute")
		}
		echoRoundTrip(t, conn, 2000)
		time.Sleep(200 * time.Millisecond)
	}
	echoRoundTrip(t, conn, 1<<18)
}

func TestFinalmaskUDPHop(t *testing.T) {
	tg := startTargets(t)
	hop := func(settings obj) obj { return fmMask("udphop", settings) }

	// The port in the proxy is one nobody listens on: the mask picks the real one.
	t.Run("perConnRemote", func(t *testing.T) {
		port := freePort(t)
		startXray(t, fmHysteriaInbound(port))
		fan := fmStartFanIn(t, port, 4)
		proxy := fmHysteria(t, freePort(t), nil, hop(obj{"mode": "perConnRemote", "remotePorts": fan.portList()}))
		checkTCP(t, proxy, tg)
		checkUDP(t, proxy, tg)
		clients, ports := fan.seen()
		require.Equal(t, 1, clients)
		require.Equal(t, 1, ports)
	})

	t.Run("intervalRemote", func(t *testing.T) {
		port := freePort(t)
		startXray(t, fmHysteriaInbound(port))
		fan := fmStartFanIn(t, port, 8)
		proxy := fmHysteria(t, fan.ports[0], nil, hop(obj{
			"mode": "perConnRemote,intervalRemote", "interval": "5-6", "remote-ports": fan.portList(),
		}))
		fmEchoUntil(t, proxy, tg, func() bool { _, ports := fan.seen(); return ports >= 3 })
		clients, _ := fan.seen()
		require.Equal(t, 1, clients, "the client socket stays the same")
	})

	// A new local socket every interval: the server sees the client address change.
	t.Run("intervalLocal", func(t *testing.T) {
		port := freePort(t)
		startXray(t, fmHysteriaInbound(port))
		fan := fmStartFanIn(t, port, 1)
		proxy := fmHysteria(t, fan.ports[0], nil, hop(obj{"mode": "intervalLocal", "interval": 5}))
		fmEchoUntil(t, proxy, tg, func() bool { clients, _ := fan.seen(); return clients >= 3 })
	})

	t.Run("local-and-remote-under-salamander", func(t *testing.T) {
		port := freePort(t)
		salamander := fmMask("salamander", obj{"password": "obfs-password"})
		startXray(t, fmHysteriaInbound(port, salamander))
		fan := fmStartFanIn(t, port, 4)
		proxy := fmHysteria(t, fan.ports[0], nil, salamander, hop(obj{
			"mode": "intervalLocal,intervalRemote", "interval": 5,
			"remoteIPs": []string{"127.0.0.1"}, "remotePorts": fmt.Sprintf("%d-%d,%s", fan.ports[0], fan.ports[0], fan.portList()),
		}))
		fmEchoUntil(t, proxy, tg, func() bool { clients, ports := fan.seen(); return clients >= 2 && ports >= 2 })
		checkUDP(t, proxy, tg)
	})

	// mKCP knows a session by the client address, so only the server port may change.
	t.Run("mkcp-intervalRemote", func(t *testing.T) {
		port := freePort(t)
		legacy := fmMask("mkcp-legacy", obj{"value": "kcp-seed"})
		startXray(t, fmKCPInbound(port, legacy))
		fan := fmStartFanIn(t, port, 8)
		proxy := fmKCP(t, fan.ports[0], obj{"raw": true}, legacy, hop(obj{
			"mode": "intervalRemote", "interval": 5, "remote-ports": fan.portList(),
		}))
		fmEchoUntil(t, proxy, tg, func() bool { _, ports := fan.seen(); return ports >= 2 })
	})
}

func TestFinalmaskUDPHopOptions(t *testing.T) {
	hop := fmMask("udphop", obj{"mode": "intervalRemote", "remote-ports": "20000-20010"})
	for name, mapping := range map[string]obj{
		"not last":             {"type": "hysteria2", "port": 443, "password": "x", "finalmask": obj{"udp": []obj{hop, fmMask("salamander", obj{"password": "obfs-password"})}}},
		"with hysteria2 ports": {"type": "hysteria2", "ports": "20000-20010", "password": "x", "finalmask": obj{"udp": []obj{hop}}},
		"masks with realm": {"type": "hysteria2", "port": 443, "password": "x",
			"realm-opts": obj{"enable": true, "server-url": "https://rendezvous.example.org", "token": "t", "realm-id": "r", "stun-servers": []string{"stun.example.org:3478"}},
			"finalmask":  obj{"udp": []obj{fmMask("salamander", obj{"password": "obfs-password"})}}},
		"short interval": {"type": "hysteria2", "port": 443, "password": "x", "finalmask": obj{"udp": []obj{fmMask("udphop", obj{"mode": "intervalLocal", "interval": 2})}}},
	} {
		t.Run(name, func(t *testing.T) {
			mapping["name"] = "xray"
			mapping["server"] = "127.0.0.1"
			_, err := adapterParse(mapping)
			require.Error(t, err)
		})
	}
}
