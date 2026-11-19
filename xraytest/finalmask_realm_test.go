package xraytest

import (
	"encoding/binary"
	"net"
	"testing"

	adapterInbound "github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/hysteria2_realm"

	"github.com/stretchr/testify/require"
)

// fmStartSTUN is a STUN server: it answers a binding request with the address
// the request came from.
func fmStartSTUN(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		const magicCookie = 0x2112A442
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n < 20 || binary.BigEndian.Uint16(buf) != 0x0001 || binary.BigEndian.Uint32(buf[4:]) != magicCookie {
				continue
			}
			ip := from.IP.To4()
			answer := make([]byte, 32)
			binary.BigEndian.PutUint16(answer, 0x0101)      // binding success response
			binary.BigEndian.PutUint16(answer[2:], 12)      // attributes length
			copy(answer[4:20], buf[4:20])                   // magic cookie and transaction id
			binary.BigEndian.PutUint16(answer[20:], 0x0020) // XOR-MAPPED-ADDRESS
			binary.BigEndian.PutUint16(answer[22:], 8)
			answer[25] = 0x01 // IPv4
			binary.BigEndian.PutUint16(answer[26:], uint16(from.Port)^(magicCookie>>16))
			binary.BigEndian.PutUint32(answer[28:], binary.BigEndian.Uint32(ip)^magicCookie)
			_, _ = pc.WriteToUDP(answer, from)
		}
	}()
	return pc.LocalAddr().String()
}

// fmStartRendezvous is the realm rendezvous server, the one mihomo ships.
func fmStartRendezvous(t *testing.T, token string) int {
	t.Helper()
	port := freePort(t)
	l, err := hysteria2_realm.New(config.Hysteria2RealmServer{
		Enable: true, Listen: loopback(port).String(), Token: token,
	}, adapterInbound.ListenConfig{}, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	return port
}

func TestFinalmaskRealm(t *testing.T) {
	tg := startTargets(t)
	const token = "realm-token"
	stun := fmStartSTUN(t)

	realm := func(rendezvous int, id string) obj {
		return fmMask("realm", obj{
			"url":         "realm+http://" + token + "@" + loopback(rendezvous).String() + "/" + id,
			"stunServers": []string{stun},
			"ipMode":      "v4",
		})
	}

	// The proxy points at a port nobody listens on: the server is found
	// through the rendezvous server.
	t.Run("hysteria", func(t *testing.T) {
		rendezvous := fmStartRendezvous(t, token)
		x := startXray(t, fmHysteriaInbound(freePort(t), realm(rendezvous, "home")))
		x.waitCount(t, "[realm]", 1)
		proxy := fmHysteria(t, freePort(t), nil, realm(rendezvous, "home"))
		checkTCP(t, proxy, tg)
		checkUDP(t, proxy, tg)
	})

	// The realm of the hysteria2 outbound itself is the same protocol.
	t.Run("hysteria2-realm-opts", func(t *testing.T) {
		rendezvous := fmStartRendezvous(t, token)
		x := startXray(t, fmHysteriaInbound(freePort(t), realm(rendezvous, "home")))
		x.waitCount(t, "[realm]", 1)
		proxy := fmHysteria(t, freePort(t), obj{"realm-opts": obj{
			"enable": true, "server-url": "http://" + loopback(rendezvous).String(),
			"token": token, "realm-id": "home", "stun-servers": []string{stun},
		}})
		checkTCP(t, proxy, tg)
		checkUDP(t, proxy, tg)
	})

	t.Run("under-salamander", func(t *testing.T) {
		rendezvous := fmStartRendezvous(t, token)
		salamander := fmMask("salamander", obj{"password": "obfs-password"})
		x := startXray(t, fmHysteriaInbound(freePort(t), salamander, realm(rendezvous, "home")))
		x.waitCount(t, "[realm]", 1)
		proxy := fmHysteria(t, freePort(t), nil, salamander, realm(rendezvous, "home"))
		checkTCP(t, proxy, tg)
	})

	t.Run("unknown-realm", func(t *testing.T) {
		rendezvous := fmStartRendezvous(t, token)
		x := startXray(t, fmHysteriaInbound(freePort(t), realm(rendezvous, "home")))
		x.waitCount(t, "[realm]", 1)
		fmCheckFails(t, fmHysteria(t, freePort(t), nil, realm(rendezvous, "office")), tg)
	})
}

func TestFinalmaskRealmOptions(t *testing.T) {
	for name, settings := range map[string]obj{
		"no url":       {"stunServers": []string{"stun.example.org:3478"}},
		"bad scheme":   {"url": "https://token@rendezvous.example.org/home", "stunServers": []string{"stun.example.org:3478"}},
		"no token":     {"url": "realm://rendezvous.example.org/home", "stunServers": []string{"stun.example.org:3478"}},
		"no realm id":  {"url": "realm://token@rendezvous.example.org", "stunServers": []string{"stun.example.org:3478"}},
		"no stun":      {"url": "realm://token@rendezvous.example.org/home"},
		"stun no port": {"url": "realm://token@rendezvous.example.org/home", "stunServers": []string{"stun.example.org"}},
		"insecure tls": {"url": "realm://token@rendezvous.example.org/home", "stunServers": []string{"stun.example.org:3478"}, "tlsConfig": obj{"allowInsecure": true}},
		"unknown tls":  {"url": "realm://token@rendezvous.example.org/home", "stunServers": []string{"stun.example.org:3478"}, "tlsConfig": obj{"disableSystemRoot": true}},
		"port mapping": {"url": "realm://token@rendezvous.example.org/home", "stunServers": []string{"stun.example.org:3478"}, "portMapping": obj{"enabled": true}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := adapterParse(obj{
				"name": "xray", "type": "hysteria2", "server": "127.0.0.1", "port": 443, "password": "x",
				"finalmask": obj{"udp": []obj{fmMask("realm", settings)}},
			})
			require.Error(t, err)
		})
	}
}
