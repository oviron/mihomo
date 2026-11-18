package xraytest

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/finalmask/mask"

	"github.com/stretchr/testify/require"
)

// The header-custom mask: a handshake (TCP) or a header (UDP) described by
// the settings, which Xray-core and mihomo take in the same shape.

// fmHeaderCustomOp is a transform, as an item of a header and as an argument
// of another transform alike.
func fmHeaderCustomOp(op string, args ...obj) obj {
	return obj{"transform": obj{"op": op, "args": args}}
}

func fmHeaderCustomU64(n uint64) obj      { return obj{"u64": n} }
func fmHeaderCustomReuse(name string) obj { return obj{"reuse": name} }
func fmHeaderCustomMeta(name string) obj  { return obj{"metadata": name} }

func fmHeaderCustomStr(s string) obj { return obj{"packet": s, "type": "str"} }

func fmHeaderCustomBE16(n int) []any { return []any{n >> 8, n & 0xFF} }

// fmHeaderCustomVless is a VLESS inbound behind the TCP mask.
func fmHeaderCustomVless(port int, flow string, settings obj) obj {
	stream := obj{"network": "raw", "finalmask": obj{"tcp": []obj{fmMask("header-custom", settings)}}}
	if flow != "" {
		stream["security"] = "tls"
		stream["tlsSettings"] = tlsSettings()
	}
	return fmInbound("vless", port, fmVlessSettings(flow), stream)
}

// fmHeaderCustomFails expects the proxy to be unable to carry a connection
// and returns the error it gave.
func fmHeaderCustomFails(t *testing.T, proxy C.ProxyAdapter, tg targets) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := proxy.DialContext(ctx, tcpMetadata(tg.tcp))
	if err != nil {
		return err
	}
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	if _, err = conn.Write([]byte("ping")); err != nil {
		return err
	}
	_, err = conn.Read(make([]byte, 4))
	require.Error(t, err, "the connection must not work")
	return err
}

func fmHeaderCustomTapReads(tap *fmTap) [][]byte {
	tap.mu.Lock()
	defer tap.mu.Unlock()
	return append([][]byte(nil), tap.reads...)
}

// fmHeaderCustomUDPTap is a UDP relay in front of the server that keeps the
// datagrams of both directions.
type fmHeaderCustomUDPTap struct {
	port int

	mu         sync.Mutex
	fromClient [][]byte
	fromServer [][]byte
}

func fmHeaderCustomStartUDPTap(t *testing.T, serverPort int) *fmHeaderCustomUDPTap {
	t.Helper()
	front, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	back, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(loopback(serverPort)))
	require.NoError(t, err)
	t.Cleanup(func() { _ = front.Close(); _ = back.Close() })
	tap := &fmHeaderCustomUDPTap{port: front.LocalAddr().(*net.UDPAddr).Port}
	var client net.Addr
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := front.ReadFrom(buf)
			if err != nil {
				return
			}
			tap.mu.Lock()
			client = addr
			tap.fromClient = append(tap.fromClient, append([]byte(nil), buf[:n]...))
			tap.mu.Unlock()
			_, _ = back.Write(buf[:n])
		}
	}()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, err := back.Read(buf)
			if errors.Is(err, net.ErrClosed) {
				return
			} else if err != nil {
				continue // an ICMP error while the server starts
			}
			tap.mu.Lock()
			to := client
			tap.fromServer = append(tap.fromServer, append([]byte(nil), buf[:n]...))
			tap.mu.Unlock()
			_, _ = front.WriteTo(buf[:n], to)
		}
	}()
	return tap
}

func (tap *fmHeaderCustomUDPTap) datagrams() (fromClient, fromServer [][]byte) {
	tap.mu.Lock()
	defer tap.mu.Unlock()
	return append([][]byte(nil), tap.fromClient...), append([][]byte(nil), tap.fromServer...)
}

func fmHeaderCustomWithin(t *testing.T, data []byte, from, to byte) {
	t.Helper()
	for _, b := range data {
		require.GreaterOrEqual(t, b, from)
		require.LessOrEqual(t, b, to)
	}
}

// A header that could never work is refused when the proxy is parsed.
func TestFinalmaskHeaderCustomRejectsBadOptions(t *testing.T) {
	for name, finalmask := range map[string]obj{
		"two kinds":            {"tcp": []obj{fmMask("header-custom", obj{"clients": []any{[]obj{{"rand": 2, "reuse": "a"}}}})}},
		"unknown op":           {"tcp": []obj{fmMask("header-custom", obj{"clients": []any{[]obj{fmHeaderCustomOp("be24", fmHeaderCustomU64(1))}}})}},
		"a number as a header": {"udp": []obj{fmMask("header-custom", obj{"client": []obj{fmHeaderCustomOp("add", fmHeaderCustomU64(1), fmHeaderCustomU64(2))}})}},
		"reuse before capture": {"tcp": []obj{fmMask("header-custom", obj{"clients": []any{[]obj{{"reuse": "a"}}}, "servers": []any{[]obj{{"rand": 2, "capture": "a"}}}})}},
		"unknown mode":         {"udp": []obj{fmMask("header-custom", obj{"mode": "suffix"})}},
		"unmeasurable":         {"udp": []obj{fmMask("header-custom", obj{"server": []obj{{"reuse": "a"}}})}},
	} {
		_, err := adapter.ParseProxy(obj{
			"name": "xray", "type": "vless", "server": "127.0.0.1", "port": 443,
			"uuid": userUUID, "finalmask": finalmask,
		})
		require.ErrorContains(t, err, "header-custom", name)
	}
}

func TestFinalmaskHeaderCustomTCP(t *testing.T) {
	tg := startTargets(t)

	// Every kind of item, on both sides: three rounds, the last of which the
	// client only listens to.
	settings := obj{
		"clients": []any{
			[]obj{
				{"packet": []any{0x16, 0x03, 0x01}},
				{"packet": "GET /", "type": "str"},
				{"packet": "0d0a", "type": "hex"},
				{"packet": "AQID", "type": "base64"},
				{"rand": 8, "randRange": "97-122", "capture": "nonce"},
				fmHeaderCustomOp("be16", fmHeaderCustomOp("add", fmHeaderCustomU64(3), fmHeaderCustomU64(5))),
				{"delay": "30-40", "reuse": "nonce"},
			},
			[]obj{
				{"reuse": "srv"}, // what the server made up comes back to it
				fmHeaderCustomOp("truncate", fmHeaderCustomReuse("nonce"), fmHeaderCustomU64(4)),
				fmHeaderCustomOp("pad", fmHeaderCustomOp("slice", fmHeaderCustomReuse("srv"), fmHeaderCustomU64(1), fmHeaderCustomU64(2)), fmHeaderCustomU64(5), obj{"bytes": "-", "type": "str"}),
			},
		},
		"servers": []any{
			[]obj{
				fmHeaderCustomStr("HTTP/1.1 200 OK\r\n"),
				{"reuse": "nonce"}, // what the client made up comes back to it
				{"rand": 6, "randRange": "48-57", "capture": "srv"},
				fmHeaderCustomOp("le32", fmHeaderCustomOp("xor32", fmHeaderCustomU64(0x01020304), fmHeaderCustomU64(0xFFFFFFFF))),
			},
			[]obj{
				fmHeaderCustomOp("concat", fmHeaderCustomReuse("srv"), obj{"bytes": []any{0}}, fmHeaderCustomReuse("nonce")),
			},
			[]obj{
				{"packet": []any{0xFF}},
				{"delay": "10-20", "rand": 3},
			},
		},
		"errors": []any{[]obj{fmHeaderCustomStr("HTTP/1.1 400 Bad Request\r\n\r\n")}},
	}

	t.Run("handshake", func(t *testing.T) {
		port := freePort(t)
		startXray(t, fmHeaderCustomVless(port, "", settings))
		tap := fmStartTap(t, port)
		proxy := fmProxy(t, obj{
			"type": "vless", "port": tap.port, "uuid": userUUID, "udp": true,
			"finalmask": obj{"tcp": []obj{fmMask("header-custom", settings)}},
		})
		checkTCP(t, proxy, tg)

		// The client spoke as the settings say. TCP keeps no write boundaries,
		// so this looks at the stream: two turns of the client, 31 and 15
		// bytes long, and then the VLESS request.
		stream := bytes.Join(fmHeaderCustomTapReads(tap), nil)
		require.Greater(t, len(stream), 46)
		require.Equal(t, []byte("\x16\x03\x01GET /\r\n\x01\x02\x03"), stream[:13])
		nonce := stream[13:21]
		fmHeaderCustomWithin(t, nonce, 'a', 'z')
		require.Equal(t, []byte{0, 8}, stream[21:23])
		require.Equal(t, nonce, stream[23:31])
		srv := stream[31:37]
		fmHeaderCustomWithin(t, srv, '0', '9')
		require.Equal(t, nonce[:4], stream[37:41])
		require.Equal(t, append(append([]byte(nil), srv[1:3]...), "---"...), stream[41:46])
		require.Equal(t, byte(0), stream[46], "the version byte of the VLESS request")

		checkUDP(t, proxy, tg)
	})

	t.Run("tls-vision", func(t *testing.T) {
		const flow = "xtls-rprx-vision"
		port := freePort(t)
		startXray(t, fmHeaderCustomVless(port, flow, settings))
		proxy := fmProxy(t, obj{
			"type": "vless", "port": port, "uuid": userUUID, "udp": true, "flow": flow,
			"tls": true, "skip-cert-verify": true, "servername": "example.org",
			"finalmask": obj{"tcp": []obj{fmMask("header-custom", settings)}},
		})
		checkTCP(t, proxy, tg)
		checkTLS(t, proxy, tg)
		checkUDP(t, proxy, tg)
	})

	// Each side takes the metadata from its own end of the connection, so the
	// same settings fit both only when they are symmetric.
	t.Run("metadata-symmetric", func(t *testing.T) {
		ports := fmHeaderCustomOp("be16", fmHeaderCustomOp("xor16", fmHeaderCustomMeta("local_port"), fmHeaderCustomMeta("remote_port")))
		addrs := fmHeaderCustomOp("be32", fmHeaderCustomOp("xor32", fmHeaderCustomMeta("src_ip4_u32"), fmHeaderCustomMeta("dst_ip4_u32")))
		settings := obj{
			"clients": []any{[]obj{ports, {"rand": 2}}},
			"servers": []any{[]obj{addrs, ports}},
		}
		port := freePort(t)
		startXray(t, fmHeaderCustomVless(port, "", settings))
		proxy := fmProxy(t, obj{
			"type": "vless", "port": port, "uuid": userUUID,
			"finalmask": obj{"tcp": []obj{fmMask("header-custom", settings)}},
		})
		checkTCP(t, proxy, tg)
	})

	// Otherwise what is remote for the client is local for the server.
	t.Run("metadata-mirrored", func(t *testing.T) {
		side := func(near, far, nearIP, farIP string) obj {
			return obj{
				"clients": []any{[]obj{
					fmHeaderCustomOp("be16", fmHeaderCustomMeta(far+"_port")),
					fmHeaderCustomOp("be32", fmHeaderCustomMeta(farIP)),
					fmHeaderCustomOp("be16", fmHeaderCustomMeta(near+"_port")),
				}},
				"servers": []any{[]obj{
					fmHeaderCustomOp("concat",
						fmHeaderCustomOp("be16", fmHeaderCustomMeta(near+"_port")),
						fmHeaderCustomOp("be32", fmHeaderCustomMeta(nearIP)),
						fmHeaderCustomOp("le16", fmHeaderCustomMeta(far+"_port"))),
				}},
			}
		}
		port := freePort(t)
		x := startXray(t, fmHeaderCustomVless(port, "", side("remote", "local", "src_ip4_u32", "dst_ip4_u32")))
		proxy := fmProxy(t, obj{
			"type": "vless", "port": port, "uuid": userUUID,
			"finalmask": obj{"tcp": []obj{fmMask("header-custom", side("local", "remote", "local_ip4_u32", "remote_ip4_u32"))}},
		})
		checkTCP(t, proxy, tg)
		require.Zero(t, x.count("header auth failed"))
	})

	hello := func(client, server string) obj {
		return obj{
			"clients": []any{[]obj{fmHeaderCustomStr(client), {"rand": 4}}},
			"servers": []any{[]obj{fmHeaderCustomStr(server)}},
			"errors":  []any{[]obj{fmHeaderCustomStr("go away")}},
		}
	}

	t.Run("wrong-client-bytes", func(t *testing.T) {
		port := freePort(t)
		x := startXray(t, fmHeaderCustomVless(port, "", hello("hello", "welcome")))
		proxy := fmProxy(t, obj{
			"type": "vless", "port": port, "uuid": userUUID,
			"finalmask": obj{"tcp": []obj{fmMask("header-custom", hello("hellO", "welcome"))}},
		})
		// The server answers with its error sequence, which is not what the
		// client waits for.
		err := fmHeaderCustomFails(t, proxy, tg)
		require.ErrorContains(t, err, "header-custom: handshake failed at servers[0]")
		x.waitCount(t, "header auth failed", 1)
	})

	t.Run("wrong-server-bytes", func(t *testing.T) {
		port := freePort(t)
		startXray(t, fmHeaderCustomVless(port, "", hello("hello", "welcome")))
		proxy := fmProxy(t, obj{
			"type": "vless", "port": port, "uuid": userUUID,
			"finalmask": obj{"tcp": []obj{fmMask("header-custom", hello("hello", "welcomE"))}},
		})
		err := fmHeaderCustomFails(t, proxy, tg)
		require.ErrorContains(t, err, "header-custom: handshake failed at servers[0]")
	})

	t.Run("no-mask-on-the-client", func(t *testing.T) {
		port := freePort(t)
		x := startXray(t, fmHeaderCustomVless(port, "", hello("hello", "welcome")))
		proxy := fmProxy(t, obj{"type": "vless", "port": port, "uuid": userUUID})
		fmCheckFails(t, proxy, tg)
		x.waitCount(t, "header auth failed", 1)
	})
}

func TestFinalmaskHeaderCustomUDP(t *testing.T) {
	tg := startTargets(t)

	// A header on every datagram: fixed bytes in each spelling, random bytes,
	// a transform, and captured values reused by their own side and by the
	// other one.
	prefix := obj{
		"client": []obj{
			{"packet": []any{0xC0, 0x00}},
			{"packet": "hy", "type": "str", "capture": "tag"},
			{"rand": 4, "randRange": "65-90"},
			fmHeaderCustomOp("be16", fmHeaderCustomOp("xor16", fmHeaderCustomU64(0x1234), fmHeaderCustomU64(0xFFFF))),
			{"reuse": "tag"},
		},
		"server": []obj{
			{"packet": "5a5a", "type": "hex"},
			{"reuse": "tag"},
			{"rand": 2, "capture": "s"},
			{"reuse": "s"},
			fmHeaderCustomOp("concat", fmHeaderCustomReuse("tag"), obj{"bytes": []any{0}}),
			{"packet": "AQI=", "type": "base64"},
		},
	}

	t.Run("prefix", func(t *testing.T) {
		port := freePort(t)
		x := startXray(t, fmHysteriaInbound(port, fmMask("header-custom", prefix)))
		tap := fmHeaderCustomStartUDPTap(t, port)
		proxy := fmHysteria(t, tap.port, nil, fmMask("header-custom", prefix))
		checkTCP(t, proxy, tg)
		checkUDP(t, proxy, tg)
		require.Zero(t, x.count("[mask] drop"))

		fromClient, fromServer := tap.datagrams()
		require.Greater(t, len(fromClient), 100)
		require.Greater(t, len(fromServer), 100)
		for _, d := range fromClient {
			require.Greater(t, len(d), 12)
			require.Equal(t, []byte("\xC0\x00hy"), d[:4])
			fmHeaderCustomWithin(t, d[4:8], 'A', 'Z')
			require.Equal(t, []byte("\xED\xCBhy"), d[8:12])
		}
		for _, d := range fromServer {
			require.Greater(t, len(d), 13)
			require.Equal(t, []byte("ZZhy"), d[:4])
			require.Equal(t, d[4:6], d[6:8])
			require.Equal(t, []byte("hy\x00\x01\x02"), d[8:13])
		}
	})

	// On mKCP, bare and under the mkcp-legacy mask, which is then the one
	// further from the wire.
	t.Run("prefix-mkcp", func(t *testing.T) {
		for _, masks := range [][]obj{
			{fmMask("header-custom", prefix)},
			{fmMask("mkcp-legacy", nil), fmMask("header-custom", prefix)},
		} {
			port := freePort(t)
			x := startXray(t, fmKCPInbound(port, masks...))
			proxy := fmKCP(t, port, obj{"raw": true}, masks...)
			checkTCP(t, proxy, tg)
			checkUDP(t, proxy, tg)
			require.Zero(t, x.count("[mask] drop"))
		}
	})

	// A handshake of two datagrams before the data, which is left alone.
	standalone := obj{
		"mode": "standalone",
		"client": []obj{
			fmHeaderCustomStr("PING"),
			{"rand": 4, "randRange": "97-122", "capture": "n"},
			fmHeaderCustomOp("le16", fmHeaderCustomU64(0x0102)),
		},
		"server": []obj{
			fmHeaderCustomStr("PONG"),
			{"reuse": "n"},
			fmHeaderCustomOp("concat", obj{"bytes": "!", "type": "str"}, fmHeaderCustomReuse("n")),
		},
	}

	t.Run("standalone", func(t *testing.T) {
		port := freePort(t)
		startXray(t, fmHysteriaInbound(port, fmMask("header-custom", standalone)))
		tap := fmHeaderCustomStartUDPTap(t, port)
		proxy := fmHysteria(t, tap.port, nil, fmMask("header-custom", standalone))
		checkTCP(t, proxy, tg)

		// handshakes returns the handshake datagrams of the client and checks
		// that the server answered each of them.
		handshakes := func() [][]byte {
			fromClient, fromServer := tap.datagrams()
			var probes [][]byte
			for _, d := range fromClient {
				if len(d) == 10 && string(d[:4]) == "PING" {
					fmHeaderCustomWithin(t, d[4:8], 'a', 'z')
					require.Equal(t, []byte{2, 1}, d[8:])
					probes = append(probes, d)
				}
			}
			var answers [][]byte
			for _, d := range fromServer {
				if len(d) == 13 && string(d[:4]) == "PONG" {
					answers = append(answers, d)
				}
			}
			require.Len(t, answers, len(probes))
			for i, d := range answers {
				n := probes[i][4:8]
				require.Equal(t, append(append(append([]byte("PONG"), n...), '!'), n...), d)
			}
			return probes
		}
		fromClient, fromServer := tap.datagrams()
		require.Greater(t, len(fromClient), 100)
		require.Equal(t, handshakes()[0], fromClient[0], "the handshake goes first")
		require.Equal(t, "PONG", string(fromServer[0][:4]))
		require.GreaterOrEqual(t, len(fromClient[1]), 1200, "then the QUIC handshake, as it is")
		require.Len(t, handshakes(), 1, "one handshake while it is fresh")

		// It is repeated once five seconds have passed.
		time.Sleep(5100 * time.Millisecond)
		checkUDP(t, proxy, tg)
		probes := handshakes()
		require.Len(t, probes, 2)
		require.NotEqual(t, probes[0], probes[1])
	})

	// Each side takes the metadata from its own end and nothing is known of
	// the addresses when a header is checked, so the settings differ: where
	// one side computes a value the other expects it literally, or captures
	// it. The server answers with the client's port as it sees it, which has
	// to be the port the client computed for itself.
	for _, mode := range []string{"prefix", "standalone"} {
		mode := mode
		t.Run("metadata-"+mode, func(t *testing.T) {
			port := freePort(t)
			x := startXray(t, fmHysteriaInbound(port, fmMask("header-custom", obj{
				"mode": mode,
				"client": []obj{
					{"packet": fmHeaderCustomBE16(port)},
					{"packet": []any{127, 0, 0, 1}},
					{"rand": 2, "capture": "p"},
				},
				"server": []obj{
					fmHeaderCustomOp("be16", fmHeaderCustomMeta("dst_port_u16")),
					fmHeaderCustomOp("be16", fmHeaderCustomMeta("src_port_u16")),
				},
			})))
			proxy := fmHysteria(t, port, nil, fmMask("header-custom", obj{
				"mode": mode,
				"client": []obj{
					fmHeaderCustomOp("be16", fmHeaderCustomMeta("remote_port")),
					fmHeaderCustomOp("be32", fmHeaderCustomMeta("remote_ip4_u32")),
					{"transform": fmHeaderCustomOp("be16", fmHeaderCustomMeta("local_port"))["transform"], "capture": "p"},
				},
				"server": []obj{
					{"packet": fmHeaderCustomBE16(port)},
					{"reuse": "p"},
				},
			}))
			checkTCP(t, proxy, tg)
			checkUDP(t, proxy, tg)
			require.Zero(t, x.count("[mask] drop"))
		})
	}

	t.Run("prefix-wrong-header", func(t *testing.T) {
		port := freePort(t)
		x := startXray(t, fmHysteriaInbound(port, fmMask("header-custom", obj{
			"client": []obj{fmHeaderCustomStr("client"), {"rand": 2}},
			"server": []obj{fmHeaderCustomStr("server")},
		})))
		proxy := fmHysteria(t, port, nil, fmMask("header-custom", obj{
			"client": []obj{fmHeaderCustomStr("clienT"), {"rand": 2}},
			"server": []obj{fmHeaderCustomStr("server")},
		}))
		fmCheckFails(t, proxy, tg)
		x.waitCount(t, "header mismatch", 1)
	})

	// The server sends its header, the client expects another one and drops
	// what comes.
	t.Run("prefix-wrong-server-header", func(t *testing.T) {
		port := freePort(t)
		startXray(t, fmHysteriaInbound(port, fmMask("header-custom", obj{
			"client": []obj{fmHeaderCustomStr("client")},
			"server": []obj{fmHeaderCustomStr("server")},
		})))
		proxy := fmHysteria(t, port, nil, fmMask("header-custom", obj{
			"client": []obj{fmHeaderCustomStr("client")},
			"server": []obj{fmHeaderCustomStr("serveR")},
		}))
		fmCheckFails(t, proxy, tg)
	})

	// A server that does not know the handshake of the client never answers
	// it, and the client sends no data without the answer.
	t.Run("standalone-wrong-header", func(t *testing.T) {
		port := freePort(t)
		startXray(t, fmHysteriaInbound(port, fmMask("header-custom", obj{
			"mode": "standalone", "client": []obj{fmHeaderCustomStr("client")}, "server": []obj{fmHeaderCustomStr("server")},
		})))
		tap := fmHeaderCustomStartUDPTap(t, port)
		proxy := fmHysteria(t, tap.port, nil, fmMask("header-custom", obj{
			"mode": "standalone", "client": []obj{fmHeaderCustomStr("clienT")}, "server": []obj{fmHeaderCustomStr("server")},
		}))
		fmCheckFails(t, proxy, tg)
		fromClient, _ := tap.datagrams()
		require.NotEmpty(t, fromClient)
		for _, d := range fromClient {
			require.Equal(t, "clienT", string(d), "nothing but the handshake is sent")
		}
	})

	t.Run("no-mask-on-the-client", func(t *testing.T) {
		port := freePort(t)
		x := startXray(t, fmHysteriaInbound(port, fmMask("header-custom", prefix)))
		proxy := fmHysteria(t, port, nil)
		fmCheckFails(t, proxy, tg)
		x.waitCount(t, "header mismatch", 1)
	})
}

// A value the client makes up for every datagram and the server sends back:
// both sides keep what was captured per peer. This needs a server that
// answers datagram by datagram, which a plain UDP inbound in front of the
// echo target is. The mask is used on a socket directly.
func TestFinalmaskHeaderCustomUDPNonce(t *testing.T) {
	tg := startTargets(t)
	for _, mode := range []string{"prefix", "standalone"} {
		mode := mode
		t.Run(mode, func(t *testing.T) {
			settings := obj{
				"mode": mode,
				"client": []obj{
					fmHeaderCustomStr("Q"),
					{"rand": 4, "capture": "id"},
					{"rand": 2, "randRange": "48-57", "capture": "seq"},
				},
				"server": []obj{
					fmHeaderCustomStr("R"),
					{"reuse": "id"},
					{"rand": 3, "capture": "s"},
					fmHeaderCustomOp("concat", fmHeaderCustomReuse("seq"), fmHeaderCustomReuse("s"), fmHeaderCustomReuse("id")),
				},
			}
			port := freePort(t)
			x := startXray(t, obj{
				"listen": "127.0.0.1", "port": port, "protocol": "dokodemo-door",
				"settings":       obj{"address": "127.0.0.1", "port": int(tg.udp.Port()), "network": "udp"},
				"streamSettings": obj{"finalmask": obj{"udp": []obj{fmMask("header-custom", settings)}}},
			})

			m, err := mask.BuildUDP("header-custom", settings)
			require.NoError(t, err)
			socket, err := net.ListenPacket("udp", "127.0.0.1:0")
			require.NoError(t, err)
			conn, err := m.WrapPacketConn(socket, loopback(port))
			require.NoError(t, err)
			defer conn.Close()

			server := net.UDPAddrFromAddrPort(loopback(port))
			buf := make([]byte, 2048)
			for i := 0; i < 30; i++ {
				data := bytes.Repeat([]byte{byte('a' + i)}, 10+i*40)
				_, err = conn.WriteTo(data, server)
				require.NoError(t, err)
				require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
				n, from, err := conn.ReadFrom(buf)
				require.NoError(t, err, "round trip %d", i)
				require.Equal(t, data, buf[:n])
				require.Equal(t, loopback(port), netip.MustParseAddrPort(from.String()))
			}
			require.Zero(t, x.count("[mask] drop"))
		})
	}
}
