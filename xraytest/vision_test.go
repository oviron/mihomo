package xraytest

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/metacubex/tls"
	"github.com/stretchr/testify/require"
)

// splitRecordConn cuts the first TLS application data record written to it in
// two writes, the first one 13 bytes long.
type splitRecordConn struct {
	net.Conn
	done bool
}

func (c *splitRecordConn) Write(p []byte) (int, error) {
	if c.done || len(p) <= 13 || p[0] != 0x17 || p[1] != 3 || p[2] != 3 {
		return c.Conn.Write(p)
	}
	c.done = true
	if _, err := c.Conn.Write(p[:13]); err != nil {
		return 0, err
	}
	n, err := c.Conn.Write(p[13:])
	return 13 + n, err
}

// TestVlessVisionTestseed checks the "testseed" option of the client: the
// Xray-core padding law and its rule for leaving the padding phase.
func TestVlessVisionTestseed(t *testing.T) {
	tg := startTargets(t)
	const flow = "xtls-rprx-vision"
	start := func(t *testing.T, testseed []int) (*xray, obj) {
		port := freePort(t)
		x := startXray(t, inbound("vless", port, obj{
			"clients":    []obj{{"id": userUUID, "flow": flow}},
			"decryption": "none",
		}, tlsStream()))
		return x, obj{
			"type": "vless", "port": port, "uuid": userUUID, "udp": true, "flow": flow,
			"tls": true, "skip-cert-verify": true, "servername": "example.org",
			"testseed": testseed,
		}
	}
	// the inner ClientHello of this test is longer than 900 bytes
	clientHellos := func(x *xray) (blocks []visionBlock) {
		for _, b := range visionClientBlocks(x) {
			if b.content >= 900 && b.content < 2000 {
				blocks = append(blocks, b)
			}
		}
		return
	}

	t.Run("default-values", func(t *testing.T) {
		x, mapping := start(t, []int{900, 500, 900, 256})
		proxy := newProxy(t, mapping)
		for i := 0; i < 6; i++ {
			checkTLS(t, proxy, tg)
		}
		checkVisionDirect(t, x)
		x.waitFor(t, "six inner ClientHello blocks", func() bool { return len(clientHellos(x)) >= 6 })
		blocks := clientHellos(x)
		require.Len(t, blocks, 6)
		padded := 0
		for _, b := range blocks {
			require.Less(t, b.padding, 256)
			if b.padding > 0 {
				padded++
			}
		}
		require.Greater(t, padded, 2, "blocks of 900 bytes and more get 0-255 bytes of padding: %v", blocks)
		checkTCP(t, proxy, tg)
		checkUDP(t, proxy, tg)
		checkUDPFullCone(t, proxy, tg)
	})

	t.Run("long-padding-for-client-hello", func(t *testing.T) {
		x, mapping := start(t, []int{2000, 500, 2000, 256})
		proxy := newProxy(t, mapping)
		for i := 0; i < 3; i++ {
			checkTLS(t, proxy, tg)
		}
		checkVisionDirect(t, x)
		x.waitFor(t, "three inner ClientHello blocks", func() bool { return len(clientHellos(x)) >= 3 })
		blocks := clientHellos(x)
		require.Len(t, blocks, 3)
		for _, b := range blocks {
			require.GreaterOrEqual(t, b.content+b.padding, 2000, "%v", b)
			require.Less(t, b.content+b.padding, 2500, "%v", b)
		}
	})

	t.Run("split-record", func(t *testing.T) {
		x, mapping := start(t, []int{900, 500, 900, 256})
		proxy := newProxy(t, mapping)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		conn, err := proxy.DialContext(ctx, tcpMetadata(tg.tls))
		require.NoError(t, err)
		defer conn.Close()
		tlsConn := tls.Client(&splitRecordConn{Conn: conn}, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
		require.NoError(t, tlsConn.HandshakeContext(ctx))
		echoRoundTrip(t, tlsConn, 4)
		echoRoundTrip(t, tlsConn, 1<<20)
		checkVisionDirect(t, x)

		// The cut record must stay inside the padding phase. Leaving it there
		// would put the rest of the record on the wire without a record header.
		var cut, direct *visionBlock
		for _, b := range visionClientBlocks(x) { // checkVisionDirect waited for the log
			b := b
			if b.content == 13 && cut == nil {
				cut = &b
			}
			if b.command == 2 && direct == nil {
				direct = &b
			}
		}
		require.NotNil(t, cut, "the 13 byte piece of the cut record")
		require.Equal(t, 0, cut.command)
		require.NotNil(t, direct)
		require.NotEqual(t, 13, direct.content)
	})
}
