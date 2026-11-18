package xraytest

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

// directTunnel stands for the tunnel of a running mihomo: it connects what it
// is handed straight to the destination, and records the metadata.
type directTunnel struct {
	mu        sync.Mutex
	metadatas []C.Metadata
	sockets   map[string]net.PacketConn
}

func (d *directTunnel) record(metadata *C.Metadata) {
	d.mu.Lock()
	d.metadatas = append(d.metadatas, *metadata)
	d.mu.Unlock()
}

func (d *directTunnel) seen() []C.Metadata {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]C.Metadata(nil), d.metadatas...)
}

func (d *directTunnel) HandleTCPConn(conn net.Conn, metadata *C.Metadata) {
	d.record(metadata)
	defer conn.Close()
	remote, err := net.DialTimeout("tcp", metadata.RemoteAddress(), 5*time.Second)
	if err != nil {
		return
	}
	N.Relay(conn, remote)
}

func (d *directTunnel) HandleUDPPacket(packet C.UDPPacket, metadata *C.Metadata) {
	defer packet.Drop()
	key := packet.LocalAddr().String()
	d.mu.Lock()
	socket := d.sockets[key]
	if socket == nil {
		var err error
		if socket, err = net.ListenPacket("udp", "0.0.0.0:0"); err != nil {
			d.mu.Unlock()
			return
		}
		if d.sockets == nil {
			d.sockets = map[string]net.PacketConn{}
		}
		d.sockets[key] = socket
		d.metadatas = append(d.metadatas, *metadata)
		go func() { // replies go back with the address they came from
			buf := make([]byte, 65535)
			for {
				n, from, err := socket.ReadFrom(buf)
				if err != nil {
					return
				}
				if _, err = packet.WriteBack(buf[:n], from); err != nil {
					return
				}
			}
		}()
	}
	d.mu.Unlock()
	_, _ = socket.WriteTo(packet.Data(), metadata.UDPAddr())
}

func (d *directTunnel) NatTable() C.NatTable { return nil }

func (d *directTunnel) close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, socket := range d.sockets {
		_ = socket.Close()
	}
}

// TestVlessReverse: the client is the bridge of a reverse proxy. It connects
// out to the server (the portal), and what enters the server's SOCKS inbound
// comes out at the client.
func TestVlessReverse(t *testing.T) {
	tg := startTargets(t)
	for _, flow := range []string{"", "xtls-rprx-vision"} {
		name := "plain"
		if flow != "" {
			name = "vision"
		}
		t.Run(name, func(t *testing.T) {
			ports := freePorts(t, 2)
			vlessPort, socksPort := ports[0], ports[1]
			client := obj{"id": userUUID, "reverse": obj{"tag": "rvs"}}
			var stream obj
			if flow != "" {
				client["flow"] = flow
				stream = tlsStream()
			}
			socks := inbound("socks", socksPort, obj{"auth": "noauth", "udp": true, "ip": "127.0.0.1"}, nil)
			socks["tag"] = "socks-in"
			x := startXrayConfig(t, obj{
				"log": obj{"loglevel": "debug"},
				"inbounds": []obj{
					inbound("vless", vlessPort, obj{"clients": []obj{client}, "decryption": "none"}, stream),
					socks,
				},
				"outbounds": []obj{freedom("direct")},
				"routing":   obj{"rules": []obj{{"inboundTag": []string{"socks-in"}, "outboundTag": "rvs"}}},
			})

			tunnel := &directTunnel{}
			defer tunnel.close()
			mapping := obj{
				"name": "bridge", "type": "vless", "server": "127.0.0.1", "port": vlessPort,
				"uuid": userUUID, "reverse": obj{"tag": "from-server"},
			}
			if flow != "" {
				mapping["flow"] = flow
				mapping["tls"] = true
				mapping["skip-cert-verify"] = true
				mapping["servername"] = "example.org"
			}
			bridge, err := adapter.ParseProxy(mapping, adapter.WithTunnelForAPI(tunnel))
			require.NoError(t, err)
			defer bridge.Close()
			x.waitCount(t, "tcp:v1.rvs.cool", 1)

			// a user of the server: through its SOCKS inbound, out at the bridge
			user := newProxy(t, obj{"type": "socks5", "port": socksPort, "udp": true})
			require.Eventually(t, func() bool { // the server needs a moment to register the reverse outbound
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				conn, err := user.DialContext(ctx, tcpMetadata(tg.tcp))
				if err != nil {
					return false
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				if _, err = conn.Write([]byte("ping")); err != nil {
					return false
				}
				buf := make([]byte, 4)
				_, err = conn.Read(buf)
				return err == nil
			}, 20*time.Second, 200*time.Millisecond)
			checkTCP(t, user, tg)
			checkTLS(t, user, tg)
			checkUDP(t, user, tg)
			checkUDPTwoTargets(t, user, tg)
			parallel(t, 6, func(t *testing.T) { checkTCP(t, user, tg) })

			seen := tunnel.seen()
			require.NotEmpty(t, seen)
			var tcp, udp bool
			for _, metadata := range seen {
				require.Equal(t, "from-server", metadata.InName)
				require.Equal(t, C.VLESS, metadata.Type)
				// never an address of this network, whatever the server claims
				require.Equal(t, "192.0.2.1", metadata.SrcIP.String())
				tcp = tcp || metadata.NetWork == C.TCP
				udp = udp || metadata.NetWork == C.UDP
			}
			require.True(t, tcp && udp, "both TCP and UDP must come out at the bridge")
			require.Equal(t, 1, x.count("tcp:v1.rvs.cool"), "one reverse connection is enough for this load")
		})
	}
}
