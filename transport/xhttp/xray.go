package xhttp

import (
	"strings"

	"github.com/metacubex/http"
)

// This file holds what makes the client read its options the way Xray-core
// reads the matching xhttpSettings.

// splitPath separates the query Xray allows in path ("/x?a=b").
func splitPath(path string) (string, string) {
	if i := strings.IndexByte(path, '?'); i >= 0 {
		return path[:i], path[i+1:]
	}
	return path, ""
}

// NormalizedQuery returns the query part of Path.
func (c *Config) NormalizedQuery() string {
	_, query := splitPath(c.Path)
	return query
}

// applyXrayDefaults fills the options that Xray defaults when it builds its
// config, on either side, so that a client and a server configured with the
// same few keys agree. Both the client and the server handler call it.
func (c *Config) applyXrayDefaults() {
	if c == nil {
		return
	}
	if c.XPaddingKey == "" {
		c.XPaddingKey = "x_padding"
	}
	if c.XPaddingHeader == "" {
		c.XPaddingHeader = "X-Padding"
	}
	if c.XPaddingPlacement == "" {
		c.XPaddingPlacement = PlacementQueryInHeader
	}
	if c.XPaddingMethod == "" {
		c.XPaddingMethod = string(PaddingMethodRepeatX)
	}
	if c.UplinkDataKey == "" {
		switch c.UplinkDataPlacement {
		case PlacementCookie:
			c.UplinkDataKey = "x_data"
		case PlacementHeader, PlacementAuto:
			c.UplinkDataKey = "X-Data"
		}
	}
	c.UplinkHTTPMethod = strings.ToUpper(c.UplinkHTTPMethod)
	c.DownloadConfig.applyXrayDefaults()
}

// ApplyBrowserAlias gives the headers of a WebSocket or HTTPUpgrade request
// the look of a browser when User-Agent is one of the names Xray-core takes
// there: chrome, firefox, safari, edge, curl or golang. Xray-core does the same
// and takes chrome when there is no User-Agent at all; here a request without
// one stays as it always was.
func ApplyBrowserAlias(header http.Header) {
	if len(header.Values("User-Agent")) > 0 {
		TryDefaultHeadersWith(header, "ws")
	}
}

// UserAgentAlias resolves the names Xray-core takes for the user agent of
// gRPC: chrome, firefox, edge and golang, which stands for the default and
// comes back empty. Anything else is returned as it is.
func UserAgentAlias(userAgent string) string {
	switch userAgent {
	case "chrome":
		return ChromeUA
	case "firefox":
		return FirefoxUA
	case "edge":
		return MSEdgeUA
	case "golang": // the user agent of the gRPC library itself
		return ""
	}
	return userAgent
}
