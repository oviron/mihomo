package xraytest

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/finalmask/xicmp"

	"github.com/stretchr/testify/require"
)

// The xicmp mask: the datagrams of mKCP and of Hysteria 2 travel in ICMP echo
// messages. The Xray server takes every echo request the host gets, so the
// checks run one after another and need root (raw ICMP sockets):
//
//	docker run --rm --sysctl net.ipv4.ping_group_range="0 2147483647" ... \
//	  go test -tags with_gvisor ./xraytest/ -run TestFinalmaskXICMP
//
// The client and the server share the loopback address, where the kernel
// answers every request as well; the client has to drop these answers.

// fmXicmpNeedSocket skips the test when the ICMP socket of the given kind
// cannot be opened for ip.
func fmXicmpNeedSocket(t *testing.T, dgram bool, ip string) {
	t.Helper()
	m, err := xicmp.New(obj{"dgram": dgram})
	if err == nil {
		var pc net.PacketConn
		pc, err = m.DialPacketConn(context.Background(), nil, netip.AddrPortFrom(netip.MustParseAddr(ip), 1))
		if err == nil {
			_ = pc.Close()
			return
		}
	}
	if dgram {
		t.Skipf("no ICMP datagram socket for %s (on Linux the group has to be in net.ipv4.ping_group_range): %v", ip, err)
	}
	t.Skipf("no raw ICMP socket for %s (needs root or CAP_NET_RAW): %v", ip, err)
}

// fmXicmpNeedServer skips the test when the Xray server cannot run: it opens
// raw sockets for both ICMPv4 and ICMPv6.
func fmXicmpNeedServer(t *testing.T) {
	t.Helper()
	xrayBin(t)
	fmXicmpNeedSocket(t, false, "127.0.0.1")
	fmXicmpNeedSocket(t, false, "::1")
}

// fmXicmpNeedIPv6 skips the test when the host has no IPv6 loopback address.
func fmXicmpNeedIPv6(t *testing.T) {
	t.Helper()
	l, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback address: %v", err)
	}
	_ = l.Close()
}

func fmXicmpProxy(t *testing.T, server string, mapping obj) C.Proxy {
	t.Helper()
	mapping["name"] = "xray"
	mapping["server"] = server
	proxy, err := adapter.ParseProxy(mapping)
	require.NoError(t, err)
	t.Cleanup(func() { _ = proxy.Close() })
	return proxy
}

// fmXicmpStartMKCP runs Xray with a VMess over mKCP inbound behind xicmp.
// mihomo's mKCP always has the "original" obfuscation, the mkcp-legacy mask
// of Xray.
func fmXicmpStartMKCP(t *testing.T, serverSettings obj) int {
	t.Helper()
	port := freePort(t)
	masks := []obj{fmMask("mkcp-legacy", nil)}
	if serverSettings != nil {
		masks = append(masks, fmMask("xicmp", serverSettings))
	}
	startXray(t, fmInbound("vmess", port, obj{"clients": []obj{{"id": userUUID}}}, obj{
		"network": "kcp", "kcpSettings": obj{}, "finalmask": obj{"udp": masks},
	}))
	return port
}

func fmXicmpMKCP(port int, clientSettings obj) obj {
	mapping := obj{
		"type": "vmess", "port": port, "uuid": userUUID, "alterId": 0, "cipher": "auto",
		"network": "kcp", "udp": true,
	}
	if clientSettings != nil {
		mapping["finalmask"] = obj{"udp": []obj{fmMask("xicmp", clientSettings)}}
	}
	return mapping
}

// fmXicmpCheckFails expects the proxy to be unable to carry a connection.
func fmXicmpCheckFails(t *testing.T, proxy C.ProxyAdapter, tg targets) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := proxy.DialContext(ctx, tcpMetadata(tg.tcp))
	if err != nil {
		return
	}
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(3*time.Second)))
	_, _ = conn.Write([]byte("ping"))
	_, err = conn.Read(make([]byte, 4))
	require.Error(t, err, "the connection must not work")
}

func TestFinalmaskXICMPMKCP(t *testing.T) {
	tg := startTargets(t)
	fmXicmpNeedServer(t)

	t.Run("raw", func(t *testing.T) {
		port := fmXicmpStartMKCP(t, obj{})
		proxy := fmXicmpProxy(t, "127.0.0.1", fmXicmpMKCP(port, obj{}))
		checkTCP(t, proxy, tg)
		checkUDP(t, proxy, tg)
	})

	t.Run("dgram", func(t *testing.T) {
		fmXicmpNeedSocket(t, true, "127.0.0.1")
		port := fmXicmpStartMKCP(t, obj{})
		proxy := fmXicmpProxy(t, "127.0.0.1", fmXicmpMKCP(port, obj{"dgram": true}))
		checkTCP(t, proxy, tg)
		checkUDP(t, proxy, tg)
	})

	// The packets go to the addresses of ips, not to the server address, where
	// nothing would answer. The server allows this client by its address.
	t.Run("ips", func(t *testing.T) {
		port := fmXicmpStartMKCP(t, obj{"ips": []string{"127.0.0.1"}})
		proxy := fmXicmpProxy(t, "192.0.2.1", fmXicmpMKCP(port, obj{"ips": []string{"127.0.0.1", "127.0.0.2", "127.0.0.3"}}))
		checkTCP(t, proxy, tg)
		checkUDP(t, proxy, tg)
	})

	t.Run("ips-dgram", func(t *testing.T) {
		fmXicmpNeedSocket(t, true, "127.0.0.1")
		port := fmXicmpStartMKCP(t, obj{})
		proxy := fmXicmpProxy(t, "192.0.2.1", fmXicmpMKCP(port, obj{"dgram": true, "IPs": []string{"127.0.0.1", "127.0.0.2"}}))
		checkTCP(t, proxy, tg)
		checkUDP(t, proxy, tg)
	})

	t.Run("ipv6", func(t *testing.T) {
		fmXicmpNeedIPv6(t)
		port := fmXicmpStartMKCP(t, obj{})
		proxy := fmXicmpProxy(t, "::1", fmXicmpMKCP(port, obj{}))
		checkTCP(t, proxy, tg)
		checkUDP(t, proxy, tg)
	})

	t.Run("ipv6-dgram", func(t *testing.T) {
		fmXicmpNeedIPv6(t)
		fmXicmpNeedSocket(t, true, "::1")
		port := fmXicmpStartMKCP(t, obj{})
		proxy := fmXicmpProxy(t, "::1", fmXicmpMKCP(port, obj{"dgram": true}))
		checkTCP(t, proxy, tg)
		checkUDP(t, proxy, tg)
	})

	// Negative controls. Without the mask on the server only the kernel
	// answers the requests, with copies the client must not take for data.
	t.Run("no-server-mask", func(t *testing.T) {
		port := fmXicmpStartMKCP(t, nil)
		fmXicmpCheckFails(t, fmXicmpProxy(t, "127.0.0.1", fmXicmpMKCP(port, obj{})), tg)
	})

	t.Run("no-client-mask", func(t *testing.T) {
		port := fmXicmpStartMKCP(t, obj{})
		fmXicmpCheckFails(t, fmXicmpProxy(t, "127.0.0.1", fmXicmpMKCP(port, nil)), tg)
	})

	// the server does not take requests from an address that is not in its list
	t.Run("server-rejects-source", func(t *testing.T) {
		port := fmXicmpStartMKCP(t, obj{"ips": []string{"192.0.2.9"}})
		fmXicmpCheckFails(t, fmXicmpProxy(t, "127.0.0.1", fmXicmpMKCP(port, obj{})), tg)
	})
}

func TestFinalmaskXICMPHysteria2(t *testing.T) {
	tg := startTargets(t)
	fmXicmpNeedServer(t)

	start := func(t *testing.T) int {
		port := freePort(t)
		startXray(t, fmInbound("hysteria", port, obj{"version": 2, "clients": []obj{{"auth": "hysteria-auth"}}}, obj{
			"network": "hysteria", "security": "tls",
			"tlsSettings":      obj{"alpn": []string{"h3"}, "certificates": tlsSettings()["certificates"]},
			"hysteriaSettings": obj{"version": 2},
			"finalmask":        obj{"udp": []obj{fmMask("xicmp", obj{})}},
		}))
		return port
	}
	hysteria2 := func(port int, clientSettings obj) obj {
		mapping := obj{
			"type": "hysteria2", "port": port, "password": "hysteria-auth",
			"sni": "example.org", "skip-cert-verify": true,
		}
		if clientSettings != nil {
			mapping["finalmask"] = obj{"udp": []obj{fmMask("xicmp", clientSettings)}}
		}
		return mapping
	}

	t.Run("raw", func(t *testing.T) {
		proxy := fmXicmpProxy(t, "127.0.0.1", hysteria2(start(t), obj{}))
		checkTCP(t, proxy, tg)
		checkUDP(t, proxy, tg)
	})

	t.Run("dgram", func(t *testing.T) {
		fmXicmpNeedSocket(t, true, "127.0.0.1")
		proxy := fmXicmpProxy(t, "127.0.0.1", hysteria2(start(t), obj{"dgram": true}))
		checkTCP(t, proxy, tg)
		checkUDP(t, proxy, tg)
	})

	t.Run("ips-ipv6-dgram", func(t *testing.T) {
		fmXicmpNeedIPv6(t)
		fmXicmpNeedSocket(t, true, "::1")
		proxy := fmXicmpProxy(t, "192.0.2.1", hysteria2(start(t), obj{"dgram": true, "ips": []string{"::1"}}))
		checkTCP(t, proxy, tg)
		checkUDP(t, proxy, tg)
	})

	t.Run("no-client-mask", func(t *testing.T) {
		fmXicmpCheckFails(t, fmXicmpProxy(t, "127.0.0.1", hysteria2(start(t), nil)), tg)
	})
}

func TestFinalmaskXICMPRejectsBadOptions(t *testing.T) {
	xicmp := []obj{fmMask("xicmp", nil)}
	for name, tc := range map[string]struct {
		udp   []obj
		extra obj
	}{
		"bad ip":   {udp: []obj{fmMask("xicmp", obj{"ips": []string{"example.org"}})}},
		"not last": {udp: []obj{fmMask("xicmp", nil), fmMask("xicmp", nil)}},
		// the ICMP sockets are not opened by the dialer of the proxy
		"dialer-proxy":   {udp: xicmp, extra: obj{"dialer-proxy": "another"}},
		"interface-name": {udp: xicmp, extra: obj{"interface-name": "eth9"}},
		"routing-mark":   {udp: xicmp, extra: obj{"routing_mark": 7}},
	} {
		t.Run(name, func(t *testing.T) {
			mapping := obj{
				"name": "xray", "type": "hysteria2", "server": "127.0.0.1", "port": 443,
				"password": "hysteria-auth", "finalmask": obj{"udp": tc.udp},
			}
			for key, value := range tc.extra {
				mapping[key] = value
			}
			_, err := adapter.ParseProxy(mapping)
			require.Error(t, err)
		})
	}
	// the same options are fine with a mask that uses the dialer
	_, err := adapter.ParseProxy(obj{
		"name": "xray", "type": "hysteria2", "server": "127.0.0.1", "port": 443, "password": "hysteria-auth",
		"interface-name": "eth9", "routing-mark": 7,
		"finalmask": obj{"udp": []obj{fmMask("salamander", obj{"password": "obfs-password"})}},
	})
	require.NoError(t, err)
}
