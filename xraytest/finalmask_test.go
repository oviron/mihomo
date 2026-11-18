package xraytest

import (
	"io"
	"net"
	"sync"
	"testing"

	"github.com/metacubex/mihomo/adapter"
	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

// The finalmask checks: a mihomo outbound with a finalmask option against an
// Xray-core inbound with the matching streamSettings.finalmask.

func fmProxy(t *testing.T, mapping obj) C.Proxy {
	t.Helper()
	mapping["name"] = "xray"
	mapping["server"] = "127.0.0.1"
	proxy, err := adapter.ParseProxy(mapping)
	require.NoError(t, err)
	t.Cleanup(func() { _ = proxy.Close() })
	return proxy
}

func fmInbound(protocol string, port int, settings obj, stream obj) obj {
	in := obj{"listen": "127.0.0.1", "port": port, "protocol": protocol, "settings": settings}
	if stream != nil {
		in["streamSettings"] = stream
	}
	return in
}

// fmMask is one entry of a finalmask list, in Xray JSON and in mihomo alike.
func fmMask(typ string, settings obj) obj {
	if settings == nil {
		return obj{"type": typ}
	}
	return obj{"type": typ, "settings": settings}
}

func fmVlessSettings(flow string) obj {
	client := obj{"id": userUUID}
	if flow != "" {
		client["flow"] = flow
	}
	return obj{"clients": []obj{client}, "decryption": "none"}
}

func TestFinalmaskRejectsBadOptions(t *testing.T) {
	for name, finalmask := range map[string]any{
		"not a map":     "fragment",
		"unknown type":  obj{"tcp": []obj{fmMask("no-such-mask", nil)}},
		"bad settings":  obj{"tcp": []obj{fmMask("fragment", obj{"length": "x"})}},
		"zero length":   obj{"tcp": []obj{fmMask("fragment", obj{"packets": "tlshello"})}},
		"bad quic":      obj{"quic-params": obj{"congestion": "cubic"}},
		"udp tcp mixed": obj{"udp": []obj{fmMask("fragment", obj{"length": "1-2"})}},
		"negative":      obj{"tcp": []obj{fmMask("fragment", obj{"length": -1})}},
		"out of bounds": obj{"tcp": []obj{fmMask("fragment", obj{"length": "1-2147483648"})}},
		"same key":      obj{"tcp": []obj{fmMask("fragment", obj{"length": 5, "max-split": 2, "maxSplit": 3})}},
		"quic window":   obj{"quic-params": obj{"init-stream-receive-window": -1}},
	} {
		t.Run(name, func(t *testing.T) {
			for _, key := range []string{"finalmask", "FinalMask"} {
				_, err := adapter.ParseProxy(obj{
					"name": "xray", "type": "vless", "server": "127.0.0.1", "port": 443,
					"uuid": userUUID, key: finalmask,
				})
				require.Error(t, err, key)
			}
		})
	}
}

// fmTap is a TCP relay in front of the server that keeps what the client
// sent first, to look at how the mask shaped it.
type fmTap struct {
	port int

	mu    sync.Mutex
	reads [][]byte // the first client reads of the first connection
}

func fmStartTap(t *testing.T, serverPort int) *fmTap {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	tap := &fmTap{port: l.Addr().(*net.TCPAddr).Port}
	first := true
	go func() {
		for {
			client, err := l.Accept()
			if err != nil {
				return
			}
			record := first
			first = false
			server, err := net.Dial("tcp", loopback(serverPort).String())
			if err != nil {
				_ = client.Close()
				continue
			}
			t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
			go func() { _, _ = io.Copy(client, server) }()
			go func() {
				buf := make([]byte, 32*1024)
				for {
					n, err := client.Read(buf)
					if n > 0 {
						if record {
							tap.mu.Lock()
							if len(tap.reads) < 64 {
								tap.reads = append(tap.reads, append([]byte(nil), buf[:n]...))
							}
							tap.mu.Unlock()
						}
						if _, werr := server.Write(buf[:n]); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	return tap
}

// readSizes returns the sizes of the first client reads.
func (tap *fmTap) readSizes() []int {
	tap.mu.Lock()
	defer tap.mu.Unlock()
	sizes := make([]int, len(tap.reads))
	for i, r := range tap.reads {
		sizes[i] = len(r)
	}
	return sizes
}

// handshakeRecords returns the payload sizes of the TLS handshake records
// the client stream starts with.
func (tap *fmTap) handshakeRecords() []int {
	tap.mu.Lock()
	defer tap.mu.Unlock()
	var stream []byte
	for _, r := range tap.reads {
		stream = append(stream, r...)
	}
	var sizes []int
	for len(stream) >= 5 && stream[0] == 22 {
		l := int(stream[3])<<8 | int(stream[4])
		if len(stream) < 5+l {
			break
		}
		sizes = append(sizes, l)
		stream = stream[5+l:]
	}
	return sizes
}
