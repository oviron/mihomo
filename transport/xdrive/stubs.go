package xdrive

import (
	"errors"

	"github.com/metacubex/http"
)

// HTTPDoer sends the requests of the remote services.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// S3Config is the s3 block of xdriveSettings.
type S3Config struct {
	Endpoint  string
	Region    string
	Bucket    string
	PathStyle bool
}

func newS3Storage(cfg *Config) (Storage, error) {
	return nil, errors.New("xdrive: s3 is not implemented yet")
}

func newTemplateStorage(cfg *Config) (Storage, error) {
	return nil, errors.New("xdrive: template is not implemented yet")
}
