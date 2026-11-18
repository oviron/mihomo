package xhttp

import (
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// xmuxTestTransport answers every request and says which connection it is.
type xmuxTestTransport struct {
	id     int64
	closed atomic.Bool
}

func (t *xmuxTestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(""))}, nil
}

func (t *xmuxTestTransport) Close() error {
	t.closed.Store(true)
	return nil
}

func xmuxTestManager(t *testing.T, cfg ReuseConfig) (*ReuseManager, *[]*xmuxTestTransport) {
	cfg.XraySemantics = true
	var made []*xmuxTestTransport
	manager, err := NewReuseManager(&cfg, func() http.RoundTripper {
		transport := &xmuxTestTransport{id: int64(len(made) + 1)}
		made = append(made, transport)
		return transport
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = manager.Close() })
	return manager, &made
}

func xmuxServedBy(rt http.RoundTripper) int64 {
	x := rt.(*ReuseTransport).xmux
	return x.held[len(x.held)-1].entry.transport.(*xmuxTestTransport).id
}

func TestXmuxDefaults(t *testing.T) {
	cfg := &ReuseConfig{XraySemantics: true}
	require.NoError(t, cfg.applyXmuxDefaults())
	assert.Equal(t, ReuseConfig{MaxConnections: "3", HMaxRequestTimes: "600-900", HMaxReusableSecs: "1800-3000", XraySemantics: true}, *cfg)

	cfg = &ReuseConfig{XraySemantics: true, MaxConcurrency: "16-32"}
	require.NoError(t, cfg.applyXmuxDefaults())
	assert.Equal(t, ReuseConfig{MaxConcurrency: "16-32", XraySemantics: true}, *cfg)

	// "0" is as good as unset, a keep-alive period alone is a setting
	cfg = &ReuseConfig{XraySemantics: true, MaxConnections: "0"}
	require.NoError(t, cfg.applyXmuxDefaults())
	assert.Equal(t, "3", cfg.MaxConnections)
	cfg = &ReuseConfig{XraySemantics: true, HKeepAlivePeriod: -1}
	require.NoError(t, cfg.applyXmuxDefaults())
	assert.Equal(t, ReuseConfig{XraySemantics: true, HKeepAlivePeriod: -1}, *cfg)

	cfg = &ReuseConfig{} // reuse-settings: nothing is filled in
	require.NoError(t, cfg.applyXmuxDefaults())
	assert.Equal(t, ReuseConfig{}, *cfg)

	_, err := NewReuseManager(&ReuseConfig{XraySemantics: true, MaxConcurrency: "1", MaxConnections: "1"}, nil)
	assert.Error(t, err)
}

// hMaxRequestTimes counts requests, and a stream moves to the next connection
// when the current one has none left.
func TestXmuxRequestLimit(t *testing.T) {
	manager, made := xmuxTestManager(t, ReuseConfig{MaxConnections: "1", HMaxRequestTimes: "2"})
	rt := manager.GetTransport()

	var served []int64
	var bodies []io.Closer
	for i := 0; i < 5; i++ {
		resp, err := rt.RoundTrip(&http.Request{})
		require.NoError(t, err)
		served = append(served, xmuxServedBy(rt))
		bodies = append(bodies, resp.Body)
	}
	assert.Equal(t, []int64{1, 1, 2, 2, 3}, served)

	// a connection is let go once its last response is closed
	assert.False(t, (*made)[0].closed.Load())
	for _, body := range bodies {
		require.NoError(t, body.Close())
		require.NoError(t, body.Close()) // closing twice is harmless
	}
	assert.True(t, (*made)[0].closed.Load())
	assert.True(t, (*made)[1].closed.Load())
	assert.False(t, (*made)[2].closed.Load())

	// dialing does not use requests up: the third connection has one left
	other := manager.GetTransport()
	_, err := other.RoundTrip(&http.Request{})
	require.NoError(t, err)
	assert.Equal(t, int64(3), xmuxServedBy(other))

	require.NoError(t, rt.(*ReuseTransport).Close())
	require.NoError(t, other.(*ReuseTransport).Close())
	assert.True(t, (*made)[2].closed.Load())
	_, err = rt.RoundTrip(&http.Request{})
	assert.Error(t, err)
}

// cMaxReuseTimes counts the first use.
func TestXmuxReuseTimes(t *testing.T) {
	manager, _ := xmuxTestManager(t, ReuseConfig{MaxConnections: "1", CMaxReuseTimes: "2"})
	var served []int64
	for i := 0; i < 5; i++ {
		rt := manager.GetTransport()
		served = append(served, xmuxServedBy(rt))
		require.NoError(t, rt.(*ReuseTransport).Close())
	}
	assert.Equal(t, []int64{1, 1, 2, 2, 3}, served)
}

// A connection past hMaxReusableSecs takes no new stream, busy or not.
func TestXmuxReusableSecs(t *testing.T) {
	manager, made := xmuxTestManager(t, ReuseConfig{MaxConnections: "1", HMaxReusableSecs: "1000"})
	first := manager.GetTransport()
	assert.Equal(t, int64(1), xmuxServedBy(manager.GetTransport()))

	first.(*ReuseTransport).entry.unreusableAt = time.Now().Add(-time.Second)
	second := manager.GetTransport()
	assert.Equal(t, int64(2), xmuxServedBy(second))

	// and the stream that holds it sends its next request elsewhere
	_, err := first.RoundTrip(&http.Request{})
	require.NoError(t, err)
	assert.Equal(t, int64(2), xmuxServedBy(first))
	assert.False(t, (*made)[0].closed.Load()) // the other stream still holds it
}

// The download leg is pooled even when the upload leg is not.
func TestDownloadPoolAlone(t *testing.T) {
	maker := func() http.RoundTripper { return &xmuxTestTransport{} }
	client, err := NewClient(&Config{
		Mode:           "packet-up",
		DownloadConfig: &Config{ReuseConfig: &ReuseConfig{MaxConnections: "1"}},
	}, maker, maker, false)
	require.NoError(t, err)
	defer client.Close()
	assert.Nil(t, client.uploadManager)
	require.NotNil(t, client.downloadManager)
	_, download, err := client.getTransport()
	require.NoError(t, err)
	assert.IsType(t, &ReuseTransport{}, download)
}

// A connection that takes no new stream makes room in max-connections at once.
func TestXmuxUsedUpLeavesPool(t *testing.T) {
	manager, made := xmuxTestManager(t, ReuseConfig{MaxConnections: "2", HMaxReusableSecs: "1000"})
	first := manager.GetTransport()
	second := manager.GetTransport()
	assert.Equal(t, []int64{1, 2}, []int64{xmuxServedBy(first), xmuxServedBy(second)})

	first.(*ReuseTransport).entry.unreusableAt = time.Now().Add(-time.Second)
	third := manager.GetTransport()
	assert.Equal(t, int64(3), xmuxServedBy(third), "the expired connection still counted")
	assert.False(t, (*made)[0].closed.Load())
	require.NoError(t, first.(*ReuseTransport).Close())
	assert.True(t, (*made)[0].closed.Load())
}

// A stream that outlives the pool does not fill it again.
func TestXmuxClosedPool(t *testing.T) {
	manager, made := xmuxTestManager(t, ReuseConfig{MaxConnections: "1", HMaxRequestTimes: "1"})
	rt := manager.GetTransport()
	_, err := rt.RoundTrip(&http.Request{})
	require.NoError(t, err)
	require.NoError(t, manager.Close())
	_, err = rt.RoundTrip(&http.Request{})
	assert.Error(t, err)
	assert.Len(t, *made, 1)
}

// xmuxCountingTransport fails the test when it is used after Close or for
// more requests than the limit.
type xmuxCountingTransport struct {
	t        *testing.T
	limit    int32
	requests atomic.Int32
	closed   atomic.Bool
}

func (c *xmuxCountingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if c.closed.Load() {
		c.t.Error("request on a closed connection")
	}
	if n := c.requests.Add(1); n > c.limit {
		c.t.Errorf("%d requests on a connection limited to %d", n, c.limit)
	}
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(""))}, nil
}

func (c *xmuxCountingTransport) Close() error {
	c.closed.Store(true)
	return nil
}

// Streams that come, send and go at the same time never exceed the request
// limit of a connection and never meet a closed one.
func TestXmuxConcurrentStreams(t *testing.T) {
	const limit = 7
	manager, err := NewReuseManager(&ReuseConfig{XraySemantics: true, MaxConnections: "3", HMaxRequestTimes: "7", CMaxReuseTimes: "4"},
		func() http.RoundTripper { return &xmuxCountingTransport{t: t, limit: limit} })
	require.NoError(t, err)
	defer manager.Close()

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for stream := 0; stream < 50; stream++ {
				rt := manager.GetTransport()
				for request := 0; request < 5; request++ {
					resp, err := rt.RoundTrip(&http.Request{})
					if err != nil {
						t.Error(err)
						return
					}
					_ = resp.Body.Close()
				}
				_ = rt.(*ReuseTransport).Close()
			}
		}()
	}
	wg.Wait()
}
