package xdrive

import (
	"strings"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/randv2"
)

// HTTPDoer sends the requests of the remote services.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// The retry policy of the remote services, as in Xray-core.
const (
	serviceMaxAttempts    = 8
	serviceInitialBackoff = 200 * time.Millisecond
	serviceMaxInflight    = 64
	serviceMaxBackoff     = 8 * time.Second
)

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

// jitter returns a delay between half of backoff and backoff.
func jitter(backoff time.Duration) time.Duration {
	half := backoff / 2
	if half <= 0 {
		return backoff
	}
	return half + time.Duration(randv2.Int64N(int64(half)))
}

func retryableStatus(status int) bool {
	switch status {
	case http.StatusTooManyRequests, http.StatusInternalServerError,
		http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

// S3Config is the s3 block of xdriveSettings.
type S3Config struct {
	Endpoint  string
	Region    string
	Bucket    string
	PathStyle bool
}

// flatten turns a path into one name for a storage without folders; both
// sides have to do it the same way.
const flatSeparator = "~"

func flatten(name string) string {
	return strings.ReplaceAll(name, "/", flatSeparator)
}
