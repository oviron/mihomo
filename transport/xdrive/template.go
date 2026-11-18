package xdrive

// The "template" service: any storage with an HTTP API, described by four
// operations (put, get, list, delete) with {name}, {prefix}, {folder},
// {secretN}, {data} and {token} filled in. Ported from Xray-core
// (transport/internet/xdrive/template.go); the template itself is the JSON of
// xdriveSettings.template, the same on both sides.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	neturl "net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/http"
)

type authTemplate struct {
	Type       string            `json:"type"`
	Header     map[string]string `json:"header"`
	Username   string            `json:"username"`
	Password   string            `json:"password"`
	TokenURL   string            `json:"tokenUrl"`
	Form       map[string]string `json:"form"`
	TokenPath  string            `json:"tokenPath"`
	ExpiryPath string            `json:"expiryPath"`
}

type opTemplate struct {
	Method     string            `json:"method"`
	URL        string            `json:"url"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
	NamesRegex string            `json:"namesRegex"`

	// HrefPath makes the operation two-step, as in the Yandex Disk REST API: the first request
	// answers with a JSON body, the URL found at HrefPath is then called with HrefMethod (GET by
	// default), carrying the payload. The URL is used as given, with neither auth nor headers.
	HrefPath   string `json:"hrefPath"`
	HrefMethod string `json:"hrefMethod"`

	presigned bool
}

type retryTemplate struct {
	Status     []int  `json:"status"`
	RateReason string `json:"rateReason"`
}

type storageTemplate struct {
	Flatten     bool          `json:"flatten"`
	Concurrency int           `json:"concurrency"`
	Auth        authTemplate  `json:"auth"`
	Put         opTemplate    `json:"put"`
	Get         opTemplate    `json:"get"`
	Delete      opTemplate    `json:"delete"`
	List        opTemplate    `json:"list"`
	Retry       retryTemplate `json:"retry"`

	names *regexp.Regexp
}

type templateStorage struct {
	client   HTTPDoer
	inflight chan struct{}
	tmpl     *storageTemplate
	folder   string
	secrets  []string

	tokenMu     sync.Mutex
	token       string
	tokenExpiry time.Time
}

func newTemplateStorage(config *Config) (Storage, error) {
	if config.HTTPClient == nil {
		return nil, errors.New("xdrive: no HTTP client for the template service")
	}
	tmpl := &storageTemplate{}
	if err := json.Unmarshal([]byte(config.Template), tmpl); err != nil {
		return nil, fmt.Errorf("xdrive: invalid template: %w", err)
	}
	if tmpl.Put.URL == "" || tmpl.Get.URL == "" || tmpl.List.URL == "" || tmpl.Delete.URL == "" {
		return nil, errors.New("xdrive: template needs put, get, list and delete operations")
	}
	if tmpl.List.NamesRegex == "" {
		return nil, errors.New("xdrive: template list needs a namesRegex")
	}
	re, err := regexp.Compile(tmpl.List.NamesRegex)
	if err != nil {
		return nil, fmt.Errorf("xdrive: bad namesRegex: %w", err)
	}
	if re.NumSubexp() < 1 {
		return nil, errors.New("xdrive: namesRegex needs one capture group")
	}
	tmpl.names = re

	conc := tmpl.Concurrency
	if conc <= 0 {
		conc = serviceMaxInflight
	}
	if conc > maxTemplateConcurrency {
		conc = maxTemplateConcurrency
	}
	return &templateStorage{
		client:   config.HTTPClient,
		inflight: make(chan struct{}, conc),
		tmpl:     tmpl,
		folder:   config.RemoteFolder,
		secrets:  config.Secrets,
	}, nil
}

const maxTemplateConcurrency = 256

func (s *templateStorage) baseVars() map[string]string {
	vars := map[string]string{"folder": s.folder}
	for i, secret := range s.secrets {
		vars["secret"+itoa(i)] = secret
	}
	return vars
}

func subst(tmpl string, vars map[string]string) string {
	if tmpl == "" || !strings.ContainsRune(tmpl, '{') {
		return tmpl
	}
	out := tmpl
	for k, v := range vars {
		out = strings.ReplaceAll(out, "{"+k+"}", v)
	}
	return out
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}

func (s *templateStorage) storedName(name string) string {
	if s.tmpl.Flatten {
		return flatten(name)
	}
	return name
}

func (s *templateStorage) retryable(status int, payload []byte) bool {
	for _, code := range s.tmpl.Retry.Status {
		if status == code {
			return true
		}
	}
	if status == http.StatusForbidden && s.tmpl.Retry.RateReason != "" {
		if reason := jsonString(payload, s.tmpl.Retry.RateReason); reason != "" {
			return true
		}
	}
	return false
}

func (s *templateStorage) authHeaders(ctx context.Context, vars map[string]string) (map[string]string, error) {
	switch s.tmpl.Auth.Type {
	case "", "none":
		return nil, nil
	case "static", "oauth2":
		if s.tmpl.Auth.Type == "oauth2" {
			token, err := s.accessToken(ctx)
			if err != nil {
				return nil, err
			}
			vars["token"] = token
		}
		headers := make(map[string]string, len(s.tmpl.Auth.Header))
		for k, v := range s.tmpl.Auth.Header {
			headers[k] = subst(v, vars)
		}
		return headers, nil
	case "basic":
		user := subst(s.tmpl.Auth.Username, vars)
		pass := subst(s.tmpl.Auth.Password, vars)
		enc := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
		return map[string]string{"Authorization": "Basic " + enc}, nil
	default:
		return nil, fmt.Errorf("unsupported auth type: %v", s.tmpl.Auth.Type)
	}
}

func (s *templateStorage) accessToken(ctx context.Context) (string, error) {
	s.tokenMu.Lock()
	defer s.tokenMu.Unlock()

	if s.token != "" && time.Now().Before(s.tokenExpiry) {
		return s.token, nil
	}

	form := make(map[string]string, len(s.tmpl.Auth.Form))
	vars := s.baseVars()
	values := strings.Builder{}
	first := true
	for k, v := range s.tmpl.Auth.Form {
		form[k] = subst(v, vars)
		if !first {
			values.WriteByte('&')
		}
		first = false
		values.WriteString(k)
		values.WriteByte('=')
		values.WriteString(form[k])
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.tmpl.Auth.TokenURL,
		strings.NewReader(values.String()))
	if err != nil {
		return "", fmt.Errorf("failed to build the token request: %w", withoutURL(err))
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch the token: %w", withoutURL(err))
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("failed to read the token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("the token endpoint answered %v: %v", resp.StatusCode, string(payload))
	}

	path := s.tmpl.Auth.TokenPath
	if path == "" {
		path = "access_token"
	}
	token := jsonString(payload, path)
	if token == "" {
		return "", fmt.Errorf("the token response has no token at %v", path)
	}

	lifetime := int64(3600)
	if s.tmpl.Auth.ExpiryPath != "" {
		if n := jsonNumber(payload, s.tmpl.Auth.ExpiryPath); n > 0 {
			lifetime = n
		}
	}
	if lifetime > 60 {
		lifetime -= 60
	}
	s.token = token
	s.tokenExpiry = time.Now().Add(time.Duration(lifetime) * time.Second)
	return s.token, nil
}

func (s *templateStorage) invalidateToken() {
	s.tokenMu.Lock()
	s.token = ""
	s.tokenMu.Unlock()
}

func (s *templateStorage) do(ctx context.Context, op *opTemplate, vars map[string]string, body []byte) (int, []byte, error) {
	backoff := serviceInitialBackoff
	var lastErr error

	url := op.URL
	if !op.presigned {
		url = subst(url, vars)
	}

	for attempt := 0; attempt < serviceMaxAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return 0, nil, ctx.Err()
			case <-time.After(jitter(backoff)):
			}
			backoff *= 2
			if backoff > serviceMaxBackoff {
				backoff = serviceMaxBackoff
			}
		}

		var authHeaders map[string]string
		if !op.presigned {
			headers, err := s.authHeaders(ctx, vars)
			if err != nil {
				lastErr = err
				continue
			}
			authHeaders = headers
		}

		method := op.Method
		if method == "" {
			method = http.MethodGet
		}

		var reader io.Reader
		if body != nil {
			reader = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, url, reader)
		if err != nil {
			return 0, nil, fmt.Errorf("failed to build request: %w", withoutURL(err))
		}
		for k, v := range authHeaders {
			req.Header.Set(k, v)
		}
		for k, v := range op.Headers {
			req.Header.Set(k, subst(v, vars))
		}

		select {
		case s.inflight <- struct{}{}:
		case <-ctx.Done():
			return 0, nil, ctx.Err()
		}
		resp, err := s.client.Do(req)
		<-s.inflight
		if err != nil {
			if ctx.Err() != nil {
				return 0, nil, ctx.Err()
			}
			lastErr = fmt.Errorf("request failed: %w", withoutURL(err))
			continue
		}
		payload, err := io.ReadAll(io.LimitReader(resp.Body, templateResponseLimit+1))
		resp.Body.Close()
		if err != nil {
			if ctx.Err() != nil {
				return 0, nil, ctx.Err()
			}
			lastErr = fmt.Errorf("failed to read response: %w", err)
			continue
		}
		if len(payload) > templateResponseLimit {
			return 0, nil, errors.New("the response exceeds the size limit")
		}

		if resp.StatusCode == http.StatusUnauthorized && s.tmpl.Auth.Type == "oauth2" && !op.presigned {
			s.invalidateToken()
			lastErr = errors.New("the service rejected the token")
			continue
		}
		if s.retryable(resp.StatusCode, payload) {
			lastErr = fmt.Errorf("the service answered %v", resp.StatusCode)
			continue
		}
		return resp.StatusCode, payload, nil
	}
	return 0, nil, lastErr
}

// withoutURL drops the URL from an error of the HTTP client or of the URL
// parser: it may carry a signature or a token in its query.
func withoutURL(err error) error {
	var urlErr *neturl.Error
	if errors.As(err, &urlErr) {
		err = urlErr.Err
	}
	// the HTTP client quotes a Location header it can't parse
	if err != nil && strings.Contains(err.Error(), "Location") {
		return errors.New("the service sent a redirect that can't be followed")
	}
	return err
}

// templateResponseLimit bounds what is read of one response: a segment,
// which a service may wrap in base64 and JSON, or a page of a listing.
const templateResponseLimit = 4*maxSegmentBytes + 1<<20

// run performs op, following its href when the operation is two-step.
func (s *templateStorage) run(ctx context.Context, op *opTemplate, vars map[string]string, body []byte) (int, []byte, error) {
	if op.HrefPath == "" {
		return s.do(ctx, op, vars, body)
	}
	status, payload, err := s.do(ctx, op, vars, nil)
	if err != nil || status < 200 || status >= 300 {
		return status, payload, err
	}
	href := jsonString(payload, op.HrefPath)
	if href == "" {
		return 0, nil, fmt.Errorf("the response has no href at %v", op.HrefPath)
	}
	return s.do(ctx, &opTemplate{Method: op.HrefMethod, URL: href, presigned: true}, vars, body)
}

func (s *templateStorage) Put(ctx context.Context, name string, data []byte) error {
	vars := s.baseVars()
	vars["name"] = s.storedName(name)

	body := data
	if s.tmpl.Put.Body != "" {
		vars["data"] = base64.StdEncoding.EncodeToString(data)
		body = []byte(subst(s.tmpl.Put.Body, vars))
	}

	status, payload, err := s.run(ctx, &s.tmpl.Put, vars, body)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("put of %v answered %v: %v", name, status, string(payload))
	}
	return nil
}

func (s *templateStorage) Get(ctx context.Context, name string) ([]byte, error) {
	vars := s.baseVars()
	vars["name"] = s.storedName(name)

	status, payload, err := s.run(ctx, &s.tmpl.Get, vars, nil)
	if err != nil {
		return nil, err
	}
	switch {
	case status >= 200 && status < 300:
		return payload, nil
	case status == http.StatusNotFound:
		return nil, errNotFound
	default:
		return nil, fmt.Errorf("get of %v answered %v: %v", name, status, string(payload))
	}
}

func (s *templateStorage) Delete(ctx context.Context, name string) error {
	vars := s.baseVars()
	vars["name"] = s.storedName(name)

	status, payload, err := s.run(ctx, &s.tmpl.Delete, vars, nil)
	if err != nil {
		return err
	}
	if status == http.StatusNotFound || (status >= 200 && status < 300) {
		return nil
	}
	return fmt.Errorf("delete of %v answered %v: %v", name, status, string(payload))
}

func (s *templateStorage) List(ctx context.Context, prefix string) ([]Entry, error) {
	vars := s.baseVars()
	flat := s.storedName(prefix)
	vars["prefix"] = flat

	status, payload, err := s.run(ctx, &s.tmpl.List, vars, nil)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("list of %v answered %v: %v", prefix, status, string(payload))
	}

	matches := s.tmpl.names.FindAllStringSubmatch(string(payload), -1)
	if !s.tmpl.Flatten {
		entries := make([]Entry, 0, len(matches))
		for _, m := range matches {
			entries = append(entries, Entry{Name: m[1]})
		}
		return entries, nil
	}

	want := flat + flatSeparator
	seen := make(map[string]bool, len(matches))
	entries := make([]Entry, 0, len(matches))
	for _, m := range matches {
		name := m[1]
		if !strings.HasPrefix(name, want) {
			continue
		}
		rest := strings.TrimPrefix(name, want)
		if rest == "" {
			continue
		}
		if cut := strings.Index(rest, flatSeparator); cut >= 0 {
			rest = rest[:cut]
		}
		if seen[rest] {
			continue
		}
		seen[rest] = true
		entries = append(entries, Entry{Name: rest})
	}
	return entries, nil
}

func (s *templateStorage) Close() error {
	closeIdle(s.client)
	return nil
}
