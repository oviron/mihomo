package outbound

import (
	"context"
	"net"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/mkcp"
)

// dialMKCP opens an mKCP connection to addr. It serves the adapters that
// carry their protocol over mKCP the way Xray-core lets any protocol do;
// VMess has the same lines in vmess.go.
func dialMKCP(ctx context.Context, dialer C.Dialer, addr string, opts MKCPOptions) (net.Conn, error) {
	raw, err := dialer.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}
	c, err := mkcp.Dial(ctx, raw, opts.Build())
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	return c, nil
}
