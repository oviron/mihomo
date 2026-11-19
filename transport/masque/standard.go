package masque

import (
	"context"
	"fmt"

	"github.com/metacubex/mihomo/common/contextutils"

	connectip "github.com/metacubex/connect-ip-go"
	"github.com/metacubex/http"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

// DefaultPath is the CONNECT-IP path of an Xray-core MASQUE inbound: the
// RFC 9484 URI template with both variables set to "*", an IP tunnel without
// a scope.
const DefaultPath = "/.well-known/masque/ip/*/*/"

// ConnectTunnelStandard sets up a CONNECT-IP tunnel as RFC 9484 defines it:
// an extended CONNECT with the "connect-ip" protocol over HTTP/3 datagrams.
// This is what an Xray-core MASQUE inbound speaks; ConnectTunnel is the
// Cloudflare WARP variant.
//
// header carries what the server asks for besides the protocol itself, such
// as Authorization. The server assigns the tunnel addresses: wait for
// LocalPrefixes of the returned connection before sending packets.
func ConnectTunnelStandard(ctx context.Context, quicConn *quic.Conn, connectUri string, header http.Header) (*http3.Transport, *connectip.Conn, error) {
	template, err := uritemplate.New(connectUri)
	if err != nil {
		return nil, nil, fmt.Errorf("connect-ip: invalid URI: %w", err)
	}
	tr := &http3.Transport{
		EnableDatagrams:    true,
		DisableCompression: true,
	}
	hconn := tr.NewClientConn(quicConn)
	// A server that keeps the connection alive and does not answer would hold
	// the request for ever: reading the response does not follow ctx.
	stop := contextutils.AfterFunc(ctx, func() {
		_ = quicConn.CloseWithError(0, "")
	})
	ipConn, _, err := dialEx(ctx, hconn, template, "connect-ip", header, false)
	if !stop() && err == nil {
		_ = ipConn.Close()
		err = context.Cause(ctx)
	}
	if err != nil {
		_ = tr.Close()
		return nil, nil, err
	}
	return tr, ipConn, nil
}
