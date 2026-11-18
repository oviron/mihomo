package xdrive

// The "local" service: a directory both sides can reach, mostly for tests.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const tempPrefix = ".xdrive-tmp-"

type localStorage struct {
	root string
}

func newLocalStorage(root string) (*localStorage, error) {
	if root == "" {
		return nil, errors.New(`xdrive: empty "remote-folder"`)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("xdrive: failed to create remote folder: %w", err)
	}
	return &localStorage{root: root}, nil
}

func (s *localStorage) resolve(name string) (string, error) {
	clean := path.Clean("/" + name)
	if clean == "/" {
		return "", fmt.Errorf("xdrive: invalid object name: %s", name)
	}
	if strings.HasPrefix(path.Base(clean), tempPrefix) {
		return "", fmt.Errorf("xdrive: reserved object name: %s", name)
	}
	return filepath.Join(s.root, filepath.FromSlash(clean[1:])), nil
}

func (s *localStorage) Put(ctx context.Context, name string, data []byte) error {
	full, err := s.resolve(name)
	if err != nil {
		return err
	}
	dir := filepath.Dir(full)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("xdrive: failed to create folder %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, tempPrefix+"*")
	if err != nil {
		return fmt.Errorf("xdrive: failed to create temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("xdrive: failed to write %s: %w", name, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("xdrive: failed to close %s: %w", name, err)
	}
	if err := os.Rename(tmpName, full); err != nil {
		return fmt.Errorf("xdrive: failed to commit %s: %w", name, err)
	}
	return nil
}

func (s *localStorage) Get(ctx context.Context, name string) ([]byte, error) {
	full, err := s.resolve(name)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(full)
	// on Windows a file that is just being renamed into place cannot be opened
	for wait := 0; err != nil && !os.IsNotExist(err) && runtime.GOOS == "windows" && wait < 200 && ctx.Err() == nil; wait++ {
		time.Sleep(10 * time.Millisecond)
		data, err = os.ReadFile(full)
	}
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errNotFound
		}
		return nil, fmt.Errorf("xdrive: failed to read %s: %w", name, err)
	}
	return data, nil
}

func (s *localStorage) Delete(ctx context.Context, name string) error {
	full, err := s.resolve(name)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(full); err != nil {
		return fmt.Errorf("xdrive: failed to delete %s: %w", name, err)
	}
	return nil
}

func (s *localStorage) List(ctx context.Context, prefix string) ([]Entry, error) {
	full, err := s.resolve(prefix)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(full)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("xdrive: failed to list %s: %w", prefix, err)
	}
	found := make([]Entry, 0, len(entries))
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), tempPrefix) {
			continue
		}
		found = append(found, Entry{Name: entry.Name()})
	}
	return found, nil
}

func (s *localStorage) Close() error {
	return nil
}
