//go:build xray_parity

// Package xrayparity checks the mihomo client against a real Xray-core server.
//
// Every test starts Xray in Docker with a server config, builds a mihomo
// outbound from a YAML snippet and pushes data through the pair.
//
//	go test -tags xray_parity -count=1 ./xrayparity/
//
// XRAY_IMAGE overrides the server image.
package xrayparity

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	C "github.com/metacubex/mihomo/constant"

	"go.yaml.in/yaml/v3"
)

const (
	defaultImage = "ghcr.io/xtls/xray-core:26.11.9"
	echoHost     = "host.docker.internal"
	testUUID     = "b831381d-6324-4d53-ad4f-8cda48b30811"
)

func image() string {
	if v := os.Getenv("XRAY_IMAGE"); v != "" {
		return v
	}
	return defaultImage
}

func docker(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// xrayTool runs a one-shot xray subcommand (x25519, mldsa65, tls ech ...) and
// returns its output.
func xrayTool(t *testing.T, args ...string) string {
	t.Helper()
	return docker(t, append([]string{"run", "--rm", image()}, args...)...)
}

// field returns the value that follows "name:" in the output of an xray tool,
// on the same line or on the next one.
func field(t *testing.T, out, name string) string {
	t.Helper()
	lines := strings.Split(out, "\n")
	for i, line := range lines {
		if !strings.HasPrefix(line, name) {
			continue
		}
		if _, v, ok := strings.Cut(line, ":"); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
		if i+1 < len(lines) {
			return strings.TrimSpace(lines[i+1])
		}
	}
	t.Fatalf("no %q in:\n%s", name, out)
	return ""
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

type xray struct {
	t    *testing.T
	name string
	Port int
}

// startXray runs Xray with the given JSON config. The config is formatted with
// one argument, the port the inbound listens on, published for TCP and UDP.
// Extra files are copied next to the config as /etc/xray/<name>.
func startXray(t *testing.T, configFormat string, files map[string][]byte) *xray {
	t.Helper()
	x := &xray{t: t, Port: freePort(t)}
	x.name = fmt.Sprintf("xrayparity-%d-%d", os.Getpid(), x.Port)

	dir := t.TempDir()
	config := strings.ReplaceAll(configFormat, "%PORT%", strconv.Itoa(x.Port))
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(config), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	port := strconv.Itoa(x.Port)
	docker(t, "create", "--name", x.name,
		"--add-host", echoHost+":host-gateway",
		"-e", "SSL_CERT_FILE=/etc/xray/cert.pem", // lets REALITY probe the local target
		"-p", "127.0.0.1:"+port+":"+port+"/tcp",
		"-p", "127.0.0.1:"+port+":"+port+"/udp",
		image(), "run", "-c", "/etc/xray/config.json")
	t.Cleanup(func() {
		if t.Failed() && x.t != nil {
			t.Logf("xray log:\n%s", x.Logs())
		}
		_ = exec.Command("docker", "rm", "-f", x.name).Run()
	})
	docker(t, "cp", dir+"/.", x.name+":/etc/xray/")
	docker(t, "start", x.name)

	deadline := time.Now().Add(15 * time.Second)
	for !strings.Contains(x.Logs(), " started") {
		if time.Now().After(deadline) {
			t.Fatalf("xray did not start:\n%s", x.Logs())
		}
		time.Sleep(100 * time.Millisecond)
	}
	for { // the published port follows the container a moment later
		c, err := net.DialTimeout("tcp", "127.0.0.1:"+port, time.Second)
		if err == nil {
			_ = c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("xray port is not published: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	return x
}

func (x *xray) Logs() string {
	out, _ := exec.Command("docker", "logs", x.name).CombinedOutput()
	return string(out)
}

// newProxy builds a mihomo outbound from YAML. "%PORT%" is replaced with the
// server port.
func newProxy(t *testing.T, x *xray, proxyYAML string) C.Proxy {
	t.Helper()
	proxy, err := parseProxy(x, proxyYAML)
	if err != nil {
		t.Fatalf("parse proxy: %v", err)
	}
	t.Cleanup(func() { _ = proxy.Close() })
	return proxy
}

func parseProxy(x *xray, proxyYAML string) (C.Proxy, error) {
	proxyYAML = strings.ReplaceAll(proxyYAML, "%PORT%", strconv.Itoa(x.Port))
	mapping := map[string]any{}
	if err := yaml.Unmarshal([]byte(proxyYAML), &mapping); err != nil {
		return nil, err
	}
	mapping["name"] = "xray"
	mapping["server"] = "127.0.0.1"
	mapping["port"] = x.Port
	return adapter.ParseProxy(mapping)
}

// echoServer returns the port of a TCP echo server the Xray container can
// reach as host.docker.internal.
func echoServer(t *testing.T) int {
	t.Helper()
	addr := "0.0.0.0:0"
	if runtime.GOOS == "darwin" { // Docker Desktop delivers to the loopback
		addr = "127.0.0.1:0"
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

// roundTrip sends size random bytes to the echo server through the proxy and
// expects them back.
func roundTrip(proxy C.Proxy, echoPort int, size int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := proxy.DialContext(ctx, &C.Metadata{
		NetWork: C.TCP,
		Type:    C.INNER,
		Host:    echoHost,
		DstPort: uint16(echoPort),
	})
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	sent := make([]byte, size)
	_, _ = rand.Read(sent)
	writeErr := make(chan error, 1)
	go func() {
		_, err := conn.Write(sent)
		writeErr <- err
	}()
	got := make([]byte, size)
	if _, err := io.ReadFull(conn, got); err != nil {
		return fmt.Errorf("read: %w", err)
	}
	if err := <-writeErr; err != nil {
		return fmt.Errorf("write: %w", err)
	}
	if !bytes.Equal(sent, got) {
		return fmt.Errorf("echo mismatch")
	}
	return nil
}

// mustRoundTrip pushes a small and a large payload, each on its own stream.
func mustRoundTrip(t *testing.T, proxy C.Proxy) {
	t.Helper()
	port := echoServer(t)
	for _, size := range []int{16, 3 << 20} {
		if err := roundTrip(proxy, port, size); err != nil {
			t.Fatalf("round trip of %d bytes: %v", size, err)
		}
	}
}
