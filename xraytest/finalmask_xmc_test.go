package xraytest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

// The xmc mask: the connection logs in like a Minecraft client before it
// carries anything. Every connection takes about half a second of scheduled
// pauses and a few hundred kilobytes of padding.

// fmXMCProfile is a player profile in the names of Xray's JSON, which mihomo
// accepts as well.
func fmXMCProfile(username string) obj {
	digest := sha256.Sum256([]byte(username))
	uuid := fmt.Sprintf("%x-%x-%x-%x-%x", digest[:4], digest[4:6], digest[6:8], digest[8:10], digest[10:16])
	return obj{
		"username":          username,
		"uuid":              uuid,
		"texturesValue":     base64.StdEncoding.EncodeToString(bytes.Repeat(digest[:], 12)),
		"texturesSignature": base64.StdEncoding.EncodeToString(bytes.Repeat(digest[:], 16)),
	}
}

func fmXMCSettings(password, hostname string, usernames ...string) obj {
	profiles := make([]obj, len(usernames))
	for i, username := range usernames {
		profiles[i] = fmXMCProfile(username)
	}
	settings := obj{"password": password, "profiles": profiles}
	if hostname != "" {
		settings["hostname"] = hostname
	}
	return settings
}

// fmXMCStart runs a VLESS inbound of Xray under the xmc mask with the server
// settings and returns it with a mihomo outbound that has the client
// settings and goes through a tap.
func fmXMCStart(t *testing.T, flow string, tls bool, server, client obj) (*xray, C.Proxy, *fmTap) {
	t.Helper()
	port := freePort(t)
	stream := obj{"network": "raw", "finalmask": obj{"tcp": []obj{fmMask("xmc", server)}}}
	if tls {
		stream["security"] = "tls"
		stream["tlsSettings"] = tlsSettings()
	}
	x := startXray(t, fmInbound("vless", port, fmVlessSettings(flow), stream))
	tap := fmStartTap(t, port)
	mapping := obj{
		"type": "vless", "port": tap.port, "uuid": userUUID, "udp": true,
		"finalmask": obj{"tcp": []obj{fmMask("xmc", client)}},
	}
	if flow != "" {
		mapping["flow"] = flow
	}
	if tls {
		mapping["tls"] = true
		mapping["skip-cert-verify"] = true
		mapping["servername"] = "example.org"
	}
	return x, fmProxy(t, mapping), tap
}

// fmXMCClientStream returns what the client of the first connection sent so
// far, however TCP cut it into reads. The tap keeps the first 64 reads.
func fmXMCClientStream(tap *fmTap) (stream []byte, complete bool) {
	tap.mu.Lock()
	defer tap.mu.Unlock()
	return bytes.Join(tap.reads, nil), len(tap.reads) < 64
}

// fmXMCCheckHandshakePacket expects the connection to begin with the
// Handshake packet of a Minecraft client of protocol 775 that wants to log in
// to host and the port it dialed. The packet is not encrypted.
func fmXMCCheckHandshakePacket(t *testing.T, tap *fmTap, host string) {
	t.Helper()
	want := []byte{0x00, 0x87, 0x06, byte(len(host))}
	want = append(want, host...)
	want = append(want, byte(tap.port>>8), byte(tap.port), 0x02)
	// a packet is its length as a varint and that many bytes
	stream, _ := fmXMCClientStream(tap)
	length, size := binary.Uvarint(stream)
	require.Greater(t, size, 0, "the connection begins with %x", stream)
	require.GreaterOrEqual(t, uint64(len(stream)-size), length)
	require.Equal(t, want, stream[size:size+int(length)])
}

// fmXMCDialError returns the error of a connection that must not work.
func fmXMCDialError(t *testing.T, proxy C.ProxyAdapter, tg targets) error {
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

func TestFinalmaskXMC(t *testing.T) {
	tg := startTargets(t)

	// A password of 8 bytes, the address the client dials as the server
	// address of the Handshake packet.
	t.Run("plain", func(t *testing.T) {
		settings := fmXMCSettings("8-bytes!", "", "Player_One")
		_, proxy, tap := fmXMCStart(t, "", false, settings, settings)
		checkTCP(t, proxy, tg)
		checkUDP(t, proxy, tg)
		fmXMCCheckHandshakePacket(t, tap, "127.0.0.1")
	})

	// A password of 32 bytes, a hostname, two profiles on both sides, TLS
	// inside the mask.
	t.Run("tls-hostname-two-profiles", func(t *testing.T) {
		settings := fmXMCSettings("0123456789abcdef0123456789abcdef", "mc.example.org", "Player_One", "second_player")
		_, proxy, tap := fmXMCStart(t, "", true, settings, settings)
		checkTCP(t, proxy, tg)
		checkUDP(t, proxy, tg)
		fmXMCCheckHandshakePacket(t, tap, "mc.example.org")
	})

	// The client logs in as a profile from the end of the server's list;
	// its settings are spelled the mihomo way. A password of 41 bytes.
	t.Run("kebab-case-last-profile", func(t *testing.T) {
		password := strings.Repeat("41 bytes ", 5)[:41]
		server := fmXMCSettings(password, "", "Player_One", "second_player", "third")
		third := fmXMCProfile("third")
		client := obj{"password": password, "profiles": []obj{{
			"username": "third", "uuid": strings.ReplaceAll(third["uuid"].(string), "-", ""),
			"textures-value": third["texturesValue"], "textures-signature": third["texturesSignature"],
		}}}
		_, proxy, _ := fmXMCStart(t, "", false, server, client)
		checkTCP(t, proxy, tg)
	})

	// Vision writes to the connection under TLS, which is the mask.
	t.Run("vision", func(t *testing.T) {
		settings := fmXMCSettings("vision-password", "mc.example.org", "Player_One")
		_, proxy, _ := fmXMCStart(t, "xtls-rprx-vision", true, settings, settings)
		checkTCP(t, proxy, tg)
		checkTLS(t, proxy, tg)
		checkUDP(t, proxy, tg)
	})

	// The server sends a keep-alive packet every 15 seconds. The client
	// answers it when a Read comes across it, here one that the caller gives
	// up on after 16 seconds, and the stream goes on.
	t.Run("keep-alive", func(t *testing.T) {
		settings := fmXMCSettings("keep-alive", "", "Player_One")
		_, proxy, tap := fmXMCStart(t, "", false, settings, settings)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		conn, err := proxy.DialContext(ctx, tcpMetadata(tg.tcp))
		require.NoError(t, err)
		defer conn.Close()
		echoRoundTrip(t, conn, 4)
		before, _ := fmXMCClientStream(tap)

		require.NoError(t, conn.SetReadDeadline(time.Now().Add(16*time.Second)))
		_, err = conn.Read(make([]byte, 4))
		require.ErrorIs(t, err, os.ErrDeadlineExceeded)
		// the answer is all the client sent meanwhile: a packet of 8 bytes
		// and its ID, encrypted
		after, complete := fmXMCClientStream(tap)
		require.True(t, complete, "the tap stopped recording")
		require.Equal(t, 10, len(after)-len(before), "bytes sent while idle")
		require.NoError(t, conn.SetReadDeadline(time.Time{}))

		echoRoundTrip(t, conn, 4)
		echoRoundTrip(t, conn, 100_000)
	})

	// With TCP Fast Open the connection would only be made by the first
	// write; the mask gets a connected one, with the address it names in
	// the Handshake packet.
	t.Run("tfo", func(t *testing.T) {
		port := freePort(t)
		settings := fmXMCSettings("tcp fast open", "", "Player_One")
		startXray(t, fmInbound("vless", port, fmVlessSettings(""), obj{
			"network": "raw", "finalmask": obj{"tcp": []obj{fmMask("xmc", settings)}},
		}))
		tap := fmStartTap(t, port)
		proxy := fmProxy(t, obj{
			"type": "vless", "port": tap.port, "uuid": userUUID, "tfo": true,
			"finalmask": obj{"tcp": []obj{fmMask("xmc", settings)}},
		})
		checkTCP(t, proxy, tg)
		fmXMCCheckHandshakePacket(t, tap, "127.0.0.1")
	})

	// The client derives another key than the server shows and stops before
	// it sends anything secret.
	t.Run("wrong-password", func(t *testing.T) {
		_, proxy, _ := fmXMCStart(t, "", false,
			fmXMCSettings("server password", "", "Player_One"),
			fmXMCSettings("client password", "", "Player_One"))
		require.ErrorContains(t, fmXMCDialError(t, proxy, tg), "server public key mismatch")
	})

	t.Run("unknown-profile", func(t *testing.T) {
		x, proxy, _ := fmXMCStart(t, "", false,
			fmXMCSettings("same password", "", "Player_One"),
			fmXMCSettings("same password", "", "stranger"))
		err := fmXMCDialError(t, proxy, tg)
		require.ErrorContains(t, err, "the server refused the login")
		require.ErrorContains(t, err, "not white-listed")
		x.waitCount(t, "unknown login profile", 1)
	})

	t.Run("no-mask-on-the-client", func(t *testing.T) {
		port := freePort(t)
		settings := fmXMCSettings("same password", "", "Player_One")
		startXray(t, fmInbound("vless", port, fmVlessSettings(""), obj{
			"network": "raw", "finalmask": obj{"tcp": []obj{fmMask("xmc", settings)}},
		}))
		proxy := fmProxy(t, obj{"type": "vless", "port": port, "uuid": userUUID})
		require.Error(t, fmXMCDialError(t, proxy, tg))
	})
}

// Xray-core 26.11.9 cannot serve a password of 33-40, 49-56, 65-72, 81-88,
// 97-104 or 113 bytes, a UUID among them: its key derivation builds the seeds
// of both primes in one array, gets two neighbouring primes and Go refuses
// such a key for every connection, which Xray then leaves open and silent.
// mihomo warns about these lengths and derives the key a correct derivation
// gives. This test pins the defect of that Xray release, not a behaviour of
// mihomo.
func TestFinalmaskXMCXrayRejects36BytePassword(t *testing.T) {
	tg := startTargets(t)
	settings := fmXMCSettings(userUUID, "", "Player_One")
	require.Len(t, settings["password"], 36)
	x, proxy, _ := fmXMCStart(t, "", false, settings, settings)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := proxy.DialContext(ctx, tcpMetadata(tg.tcp))
	if err == nil {
		defer conn.Close()
		require.NoError(t, conn.SetDeadline(time.Now().Add(3*time.Second)))
		if _, err = conn.Write([]byte("ping")); err == nil {
			_, err = conn.Read(make([]byte, 4))
		}
	}
	if err == nil {
		t.Fatal("this Xray serves a 36 byte xmc password: its key derivation is fixed. " +
			"Turn this test into a positive one and drop the warning about such passwords " +
			"(xrayRejectsPasswordLength in transport/finalmask/xmc)")
	}
	if x.count("|p - q| too small") == 0 {
		t.Logf("the connection failed with %v; waiting for Xray to log why. If the message does not come, "+
			"this Xray fails on a 36 byte password in another way than 26.11.9 did", err)
	}
	x.waitCount(t, "parse rsa private key: crypto/rsa: |p - q| too small", 1)
}
