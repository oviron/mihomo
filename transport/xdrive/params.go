package xdrive

import "time"

// The defaults and the limits of Xray-core.
const (
	defaultSegmentBytes    = 512 * 1024
	defaultFlushInterval   = 20 * time.Millisecond
	defaultMinPollInterval = 50 * time.Millisecond
	defaultMaxPollInterval = 500 * time.Millisecond
	defaultEagerWindow     = 2 * time.Second
	defaultHoleTimeout     = 30 * time.Second
	defaultConcurrency     = 8

	maxSegmentBytes = 16 * 1024 * 1024
	maxConcurrency  = 256
)

type params struct {
	segmentBytes    int
	flushInterval   time.Duration
	minPollInterval time.Duration
	maxPollInterval time.Duration
	eagerWindow     time.Duration
	holeTimeout     time.Duration
	concurrency     int
}

func millis(value uint32, fallback time.Duration) time.Duration {
	if value == 0 {
		return fallback
	}
	return time.Duration(value) * time.Millisecond
}

func capped(value uint32, fallback, limit int) int {
	if value == 0 {
		return fallback
	}
	if value > uint32(limit) {
		return limit
	}
	return int(value)
}

func paramsFromConfig(c *Config) params {
	p := params{
		segmentBytes:    capped(c.SegmentBytes, defaultSegmentBytes, maxSegmentBytes),
		flushInterval:   millis(c.FlushIntervalMs, defaultFlushInterval),
		minPollInterval: millis(c.PollIntervalMs, defaultMinPollInterval),
		maxPollInterval: millis(c.MaxPollIntervalMs, defaultMaxPollInterval),
		eagerWindow:     millis(c.EagerWindowMs, defaultEagerWindow),
		holeTimeout:     millis(c.HoleTimeoutMs, defaultHoleTimeout),
		concurrency:     capped(c.Concurrency, defaultConcurrency, maxConcurrency),
	}
	if p.maxPollInterval < p.minPollInterval {
		p.maxPollInterval = p.minPollInterval
	}
	return p
}
