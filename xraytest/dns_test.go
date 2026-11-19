package xraytest

import (
	"encoding/binary"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"

	_ "github.com/metacubex/mihomo/config" // lets a proxy parse its "dns" option

	"github.com/stretchr/testify/require"
)

// dnsServer answers every A query with one address and counts the queries.
type dnsServer struct {
	addr    netip.AddrPort
	queries atomic.Int32
}

func startDNS(t *testing.T, answer netip.Addr) *dnsServer {
	t.Helper()
	pc, err := net.ListenPacket("udp", "0.0.0.0:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })
	s := &dnsServer{addr: loopback(pc.LocalAddr().(*net.UDPAddr).Port)}
	ip := answer.As4()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			query := buf[:n]
			if n < 12 || binary.BigEndian.Uint16(query[4:]) != 1 {
				continue
			}
			end := 12 // the question: name, type, class
			for end < n && query[end] != 0 {
				end += int(query[end]) + 1
			}
			end += 5
			if end > n {
				continue
			}
			s.queries.Add(1)
			reply := append([]byte(nil), query[:end]...)
			reply[2], reply[3] = 0x81, 0x80 // response, recursion available
			binary.BigEndian.PutUint16(reply[6:], 0)
			binary.BigEndian.PutUint16(reply[8:], 0)
			binary.BigEndian.PutUint16(reply[10:], 0)
			if binary.BigEndian.Uint16(query[end-4:]) == 1 { // type A
				binary.BigEndian.PutUint16(reply[6:], 1)
				reply = append(reply, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
				reply = append(reply, ip[:]...)
			}
			_, _ = pc.WriteTo(reply, from)
		}
	}()
	return s
}
