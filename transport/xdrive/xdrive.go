// Package xdrive is the client of the XDRIVE transport of Xray-core: a stream
// carried by objects in a storage both sides can reach, a directory, an S3
// bucket or any HTTP API described by a template. The client and the server
// never connect to each other.
//
// A session is announced by an empty object sessions/<unix nanos>-<id>. The
// client then writes numbered segments to streams/<id>/c2s and reads those the
// server writes to streams/<id>/s2c, each side deleting what it has read:
//
//	streams/<id>/c2s/000000000.seg   a segment
//	streams/<id>/c2s/000000007.end   no more segments
//	streams/<id>/c2s/000000003.err   segment 3 could not be stored
//
// Nothing here encrypts or authenticates the stream, the proxy protocol has to:
// Xray-core accepts only VLESS with its encryption over this transport. The
// slot rings Xray-core uses on Google Drive are not implemented; that backend
// is not either.
package xdrive

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"time"
)

const (
	sessionsDir = "sessions"
	streamsDir  = "streams"
	uplinkDir   = "c2s"
	downlinkDir = "s2c"
)

var errNotFound = errors.New("object not found")

// Entry is an object in a listing. Inline holds its content when the storage
// returned it with the listing.
type Entry struct {
	Name   string
	Inline []byte
}

// Storage is where the objects of the sessions live. List returns the names
// right under prefix, without it.
type Storage interface {
	Put(ctx context.Context, name string, data []byte) error
	Get(ctx context.Context, name string) ([]byte, error)
	Delete(ctx context.Context, name string) error
	List(ctx context.Context, prefix string) ([]Entry, error)
	Close() error
}

// Config holds the xdriveSettings of Xray-core a client needs. The zero
// values of the numbers stand for the defaults of Xray-core.
type Config struct {
	Service      string // local, s3 or template
	RemoteFolder string
	Secrets      []string

	SegmentBytes      uint32
	FlushIntervalMs   uint32
	PollIntervalMs    uint32
	MaxPollIntervalMs uint32
	Concurrency       uint32
	EagerWindowMs     uint32
	HoleTimeoutMs     uint32

	S3       *S3Config
	Template string // JSON, for the template service

	// HTTPClient reaches the storage of the s3 and template services.
	HTTPClient HTTPDoer
}

// Client opens sessions on a storage.
type Client struct {
	storage Storage
	params  params
	ctx     context.Context // of the sessions, ends with Close
	cancel  context.CancelFunc
}

func NewClient(cfg Config) (*Client, error) {
	var storage Storage
	var err error
	switch cfg.Service {
	case "local":
		storage, err = newLocalStorage(cfg.RemoteFolder)
	case "s3":
		storage, err = newS3Storage(&cfg)
	case "template":
		storage, err = newTemplateStorage(&cfg)
	case "google-drive", "Google Drive":
		err = errors.New(`xdrive: the "google-drive" service is not supported, use "s3" or "template"`)
	default:
		err = fmt.Errorf(`xdrive: unknown service %q, use "s3", "template" or "local"`, cfg.Service)
	}
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Client{storage: storage, params: paramsFromConfig(&cfg), ctx: ctx, cancel: cancel}, nil
}

func newSessionID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func announceName(session string, at time.Time) string {
	return fmt.Sprintf("%s/%d-%s", sessionsDir, at.UnixNano(), session)
}

// Dial announces a new session and returns its stream.
func (c *Client) Dial(ctx context.Context) (net.Conn, error) {
	session, err := newSessionID()
	if err != nil {
		return nil, err
	}
	if err := c.storage.Put(ctx, announceName(session, time.Now()), nil); err != nil {
		return nil, fmt.Errorf("xdrive: failed to announce session %s: %w", session, err)
	}
	prefix := streamsDir + "/" + session
	return newConn(c.ctx, c.storage, prefix+"/"+uplinkDir, prefix+"/"+downlinkDir, c.params), nil
}

// Close ends the sessions that are still open and lets go of the storage.
func (c *Client) Close() error {
	c.cancel()
	return c.storage.Close()
}
