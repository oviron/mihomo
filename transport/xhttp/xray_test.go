package xhttp

import (
	"context"
	"errors"
	"testing"

	"github.com/metacubex/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type recordingTransport struct{ requests chan *http.Request }

func (r recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r.requests <- req
	return nil, errors.New("recorded")
}

// The query of path must reach the wire as a query in every mode.
func TestPathQueryIsSent(t *testing.T) {
	for _, mode := range []string{"packet-up", "stream-up", "stream-one"} {
		recorder := recordingTransport{requests: make(chan *http.Request, 4)}
		client, err := NewClient(&Config{Host: "example.org", Path: "/x?token=abc", Mode: mode},
			func() http.RoundTripper { return recorder }, nil, false)
		require.NoError(t, err)
		_, err = client.Dial(context.Background())
		require.Error(t, err)
		req := <-recorder.requests
		assert.Equal(t, "token=abc", req.URL.RawQuery, mode)
		assert.Regexp(t, "^/x/", req.URL.Path, mode)
		_ = client.Close()
	}
}

func TestPathWithQuery(t *testing.T) {
	c := &Config{Path: "/x?a=b&c=d"}
	assert.Equal(t, "/x/", c.NormalizedPath())
	assert.Equal(t, "a=b&c=d", c.NormalizedQuery())

	c = &Config{Path: "x", SessionPlacement: PlacementHeader, SeqPlacement: PlacementHeader}
	assert.Equal(t, "/x", c.NormalizedPath())
	assert.Equal(t, "", c.NormalizedQuery())
}

func TestXrayDefaults(t *testing.T) {
	download := &Config{UplinkDataPlacement: PlacementCookie}
	c := &Config{UplinkDataPlacement: PlacementHeader, UplinkHTTPMethod: "put", DownloadConfig: download}
	c.applyXrayDefaults()
	assert.Equal(t, "x_padding", c.XPaddingKey)
	assert.Equal(t, "X-Padding", c.XPaddingHeader)
	assert.Equal(t, PlacementQueryInHeader, c.XPaddingPlacement)
	assert.Equal(t, "repeat-x", c.XPaddingMethod)
	assert.Equal(t, "X-Data", c.UplinkDataKey)
	assert.Equal(t, "PUT", c.UplinkHTTPMethod)
	assert.Equal(t, "x_data", download.UplinkDataKey)

	c = &Config{XPaddingKey: "k", XPaddingHeader: "H", XPaddingPlacement: PlacementCookie, XPaddingMethod: "tokenish", UplinkDataKey: "D"}
	c.applyXrayDefaults()
	assert.Equal(t, Config{XPaddingKey: "k", XPaddingHeader: "H", XPaddingPlacement: PlacementCookie, XPaddingMethod: "tokenish", UplinkDataKey: "D"}, *c)

	c = &Config{} // data in the body needs no key
	c.applyXrayDefaults()
	assert.Equal(t, "", c.UplinkDataKey)
}
