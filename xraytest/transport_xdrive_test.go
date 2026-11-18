package xraytest

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

// trVlessEnc returns a decryption/encryption pair of VLESS Encryption, which
// the xdrive transport requires.
func trVlessEnc(t *testing.T) (decryption, encryption string) {
	t.Helper()
	out := trXrayTool(t, "vlessenc")
	dec := regexp.MustCompile(`"decryption": "([^"]+)"`).FindStringSubmatch(out)
	enc := regexp.MustCompile(`"encryption": "([^"]+)"`).FindStringSubmatch(out)
	require.NotNil(t, dec, out)
	require.NotNil(t, enc, out)
	return dec[1], enc[1]
}

// trXDriveServer starts an Xray inbound on the xdrive transport with the given
// xdriveSettings.
func trXDriveServer(t *testing.T, settings obj) (encryption string) {
	t.Helper()
	decryption, encryption := trVlessEnc(t)
	startXray(t, obj{
		"listen": "127.0.0.1", "port": freePort(t), "protocol": "vless",
		"settings":       obj{"clients": []obj{{"id": userUUID}}, "decryption": decryption},
		"streamSettings": obj{"network": "xdrive", "xdriveSettings": settings},
	})
	return encryption
}

func trXDriveProxy(t *testing.T, encryption string, opts obj) C.Proxy {
	t.Helper()
	proxy, err := adapter.ParseProxy(map[string]any{
		"name": "xray", "type": "vless", "uuid": userUUID, "encryption": encryption,
		"server": "storage.invalid", "port": 443, // not dialed
		"network": "xdrive", "xdrive-opts": map[string]any(opts),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = proxy.Close() })
	return proxy
}

// trXDriveCheck pushes streams through the storage: one after another and
// several at once, each a session of its own.
func trXDriveCheck(t *testing.T, proxy C.Proxy, tg targets) {
	t.Helper()
	require.NoError(t, trRoundTrip(proxy, tg, 16, 30*time.Second))
	require.NoError(t, trRoundTrip(proxy, tg, 3<<20, 60*time.Second))
	errs := make(chan error, 4)
	for i := 0; i < cap(errs); i++ {
		go func() { errs <- trRoundTrip(proxy, tg, 256<<10, 60*time.Second) }()
	}
	for i := 0; i < cap(errs); i++ {
		require.NoError(t, <-errs)
	}
}

// The local service: client and server share a directory. The client runs
// plain VLESS streams, one session each, without Mux.Cool.
func TestTransportXDriveLocal(t *testing.T) {
	tg := startTargets(t)
	folder := t.TempDir()
	encryption := trXDriveServer(t, obj{"service": "local", "remoteFolder": folder})
	proxy := trXDriveProxy(t, encryption, obj{"service": "local", "remote-folder": folder})
	trXDriveCheck(t, proxy, tg)

	// both sides delete what they have read: nothing piles up
	time.Sleep(time.Second)
	entries, err := os.ReadDir(folder + "/sessions")
	require.NoError(t, err)
	require.Empty(t, entries, "announcements left behind")
}

func TestTransportXDriveNeedsEncryption(t *testing.T) {
	_, err := adapter.ParseProxy(map[string]any{
		"name": "xray", "type": "vless", "uuid": userUUID, "server": "storage.invalid", "port": 443,
		"network": "xdrive", "xdrive-opts": map[string]any{"service": "local", "remote-folder": t.TempDir()},
	})
	require.ErrorContains(t, err, "encryption")
}

// trObjects is the content of a fake storage service.
type trObjects struct {
	mu      sync.Mutex
	objects map[string][]byte
	puts    int
	failed  []string // requests the service refused
}

func (o *trObjects) refuse(w http.ResponseWriter, status int, why string) {
	o.mu.Lock()
	o.failed = append(o.failed, why)
	o.mu.Unlock()
	http.Error(w, why, status)
}

func trServe(t *testing.T, handler http.Handler) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := &http.Server{Handler: handler}
	go func() { _ = server.Serve(l) }()
	t.Cleanup(func() { _ = server.Close() })
	return "http://" + l.Addr().String()
}

const (
	trS3AccessKey = "AKIAXRAYTEST"
	trS3SecretKey = "secret/key+of=the-test"
	trS3Region    = "eu-test-1"
)

// trS3Signature recomputes the AWS Signature Version 4 of a request from what
// was sent, the way an S3 service checks it.
func trS3Signature(r *http.Request, signedHeaders string) string {
	mac := func(key []byte, value string) []byte {
		h := hmac.New(sha256.New, key)
		h.Write([]byte(value))
		return h.Sum(nil)
	}
	hash := func(value string) string {
		sum := sha256.Sum256([]byte(value))
		return hex.EncodeToString(sum[:])
	}
	var headers strings.Builder
	for _, name := range strings.Split(signedHeaders, ";") {
		value := r.Header.Get(name)
		if name == "host" {
			value = r.Host
		}
		headers.WriteString(name + ":" + strings.Join(strings.Fields(value), " ") + "\n")
	}
	stamp := r.Header.Get("X-Amz-Date")
	canonical := r.Method + "\n" + r.URL.EscapedPath() + "\n" + r.URL.RawQuery + "\n" +
		headers.String() + "\n" + signedHeaders + "\n" + r.Header.Get("X-Amz-Content-Sha256")
	scope := stamp[:8] + "/" + trS3Region + "/s3/aws4_request"
	key := mac(mac(mac(mac([]byte("AWS4"+trS3SecretKey), stamp[:8]), trS3Region), "s3"), "aws4_request")
	return hex.EncodeToString(mac(key, "AWS4-HMAC-SHA256\n"+stamp+"\n"+scope+"\n"+hash(canonical)))
}

// trS3 is a path-style S3 service: PUT, GET and DELETE of objects and
// ListObjectsV2 with a delimiter, all behind a checked signature.
func trS3(t *testing.T, bucket string) (endpoint string, store *trObjects) {
	store = &trObjects{objects: map[string][]byte{}}
	authorization := regexp.MustCompile(`^AWS4-HMAC-SHA256 Credential=([^/]+)/\S+, SignedHeaders=(\S+), Signature=([0-9a-f]+)$`)
	endpoint = trServe(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		m := authorization.FindStringSubmatch(r.Header.Get("Authorization"))
		sum := sha256.Sum256(body)
		switch {
		case m == nil || m[1] != trS3AccessKey:
			store.refuse(w, http.StatusForbidden, "no credential: "+r.Header.Get("Authorization"))
			return
		case hex.EncodeToString(sum[:]) != r.Header.Get("X-Amz-Content-Sha256"):
			store.refuse(w, http.StatusBadRequest, "payload hash")
			return
		case trS3Signature(r, m[2]) != m[3]:
			store.refuse(w, http.StatusForbidden, "signature of "+r.Method+" "+r.URL.String())
			return
		}
		key, ok := strings.CutPrefix(r.URL.Path, "/"+bucket+"/")
		if !ok {
			store.refuse(w, http.StatusNotFound, "bucket: "+r.URL.Path)
			return
		}
		store.mu.Lock()
		defer store.mu.Unlock()
		switch {
		case r.Method == http.MethodPut:
			store.objects[key] = body
			store.puts++
		case r.Method == http.MethodDelete:
			delete(store.objects, key)
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && key == "" && r.URL.Query().Get("list-type") == "2":
			prefix, delimiter := r.URL.Query().Get("prefix"), r.URL.Query().Get("delimiter")
			var keys, prefixes []string
			seen := map[string]bool{}
			for name := range store.objects {
				rest, ok := strings.CutPrefix(name, prefix)
				if !ok {
					continue
				}
				if i := strings.Index(rest, delimiter); delimiter != "" && i >= 0 {
					if common := prefix + rest[:i+1]; !seen[common] {
						seen[common] = true
						prefixes = append(prefixes, common)
					}
					continue
				}
				keys = append(keys, name)
			}
			var out strings.Builder
			out.WriteString(`<?xml version="1.0" encoding="UTF-8"?><ListBucketResult><IsTruncated>false</IsTruncated>`)
			for _, name := range keys {
				out.WriteString("<Contents><Key>" + name + "</Key></Contents>")
			}
			for _, name := range prefixes {
				out.WriteString("<CommonPrefixes><Prefix>" + name + "</Prefix></CommonPrefixes>")
			}
			out.WriteString("</ListBucketResult>")
			_, _ = w.Write([]byte(out.String()))
		case r.Method == http.MethodGet:
			data, ok := store.objects[key]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`<Error><Code>NoSuchKey</Code></Error>`))
				return
			}
			_, _ = w.Write(data)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	return endpoint, store
}

// The s3 service: both sides sign their requests to an S3-compatible storage.
func TestTransportXDriveS3(t *testing.T) {
	tg := startTargets(t)
	endpoint, store := trS3(t, "bucket")
	secrets := []string{trS3AccessKey, trS3SecretKey}
	encryption := trXDriveServer(t, obj{
		"service": "s3", "remoteFolder": "tunnel/a b", "secrets": secrets,
		"s3": obj{"endpoint": endpoint, "region": trS3Region, "bucket": "bucket"},
	})
	proxy := trXDriveProxy(t, encryption, obj{
		"service": "s3", "remote-folder": "tunnel/a b", "secrets": secrets,
		"s3": obj{"endpoint": endpoint, "region": trS3Region, "bucket": "bucket"},
	})
	trXDriveCheck(t, proxy, tg)

	store.mu.Lock()
	defer store.mu.Unlock()
	require.Empty(t, store.failed, "requests the storage refused")
	require.Greater(t, store.puts, 10)
}

// The template service: a storage with an HTTP API of its own, here one that
// has no folders (flatten) and wants a token in a header.
func TestTransportXDriveTemplate(t *testing.T) {
	tg := startTargets(t)
	store := &trObjects{objects: map[string][]byte{}}
	base := trServe(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Token") != "the-token" {
			store.refuse(w, http.StatusUnauthorized, "token of "+r.Method+" "+r.URL.String())
			return
		}
		store.mu.Lock()
		defer store.mu.Unlock()
		if r.URL.Path == "/list" {
			var out strings.Builder
			out.WriteString(`{"items":[`)
			first := true
			for name := range store.objects {
				if strings.HasPrefix(name, r.URL.Query().Get("prefix")) {
					if !first {
						out.WriteString(",")
					}
					first = false
					out.WriteString(`{"name":"` + name + `"}`)
				}
			}
			out.WriteString("]}")
			_, _ = w.Write([]byte(out.String()))
			return
		}
		name, ok := strings.CutPrefix(r.URL.Path, "/o/")
		if !ok || strings.Contains(name, "/") {
			store.refuse(w, http.StatusBadRequest, "name: "+r.URL.Path)
			return
		}
		switch r.Method {
		case http.MethodPut:
			store.objects[name], _ = io.ReadAll(r.Body)
			store.puts++
		case http.MethodDelete:
			delete(store.objects, name)
		case http.MethodGet:
			data, ok := store.objects[name]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write(data)
		}
	}))
	template := obj{
		"flatten": true,
		"auth":    obj{"type": "static", "header": obj{"X-Token": "{secret0}"}},
		"put":     obj{"method": "PUT", "url": base + "/o/{name}"},
		"get":     obj{"url": base + "/o/{name}"},
		"delete":  obj{"method": "DELETE", "url": base + "/o/{name}"},
		"list":    obj{"url": base + "/list?prefix={prefix}", "namesRegex": `"name":"([^"]+)"`},
	}
	encryption := trXDriveServer(t, obj{"service": "template", "remoteFolder": "unused", "secrets": []string{"the-token"}, "template": template})
	proxy := trXDriveProxy(t, encryption, obj{"service": "template", "remote-folder": "unused", "secrets": []string{"the-token"}, "template": map[string]any(template)})
	trXDriveCheck(t, proxy, tg)

	store.mu.Lock()
	defer store.mu.Unlock()
	require.Empty(t, store.failed, "requests the storage refused")
	require.Greater(t, store.puts, 10)
}
