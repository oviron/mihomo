package dialer

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	D "github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeResolver answers SRV and TXT questions from a zone file and resolves
// every name to the loopback.
type fakeResolver struct {
	records []string
	asked   []string
}

func (r *fakeResolver) ExchangeContext(ctx context.Context, m *D.Msg) (*D.Msg, error) {
	question := m.Question[0]
	r.asked = append(r.asked, D.TypeToString[question.Qtype]+" "+question.Name)
	reply := new(D.Msg)
	reply.SetReply(m)
	for _, record := range r.records {
		rr, err := D.NewRR(record)
		if err != nil {
			return nil, err
		}
		if rr.Header().Name == question.Name && rr.Header().Rrtype == question.Qtype {
			reply.Answer = append(reply.Answer, rr)
		}
	}
	if len(reply.Answer) == 0 {
		return nil, errors.New("no such record")
	}
	return reply, nil
}

func (r *fakeResolver) LookupIP(ctx context.Context, host string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
}

func (r *fakeResolver) LookupIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	return r.LookupIP(ctx, host)
}

func (r *fakeResolver) LookupIPv6(ctx context.Context, host string) ([]netip.Addr, error) {
	return nil, errors.New("no IPv6")
}

func (r *fakeResolver) ResolveECH(ctx context.Context, host string) ([]byte, error) {
	return nil, errors.New("no ECH")
}

func (r *fakeResolver) Invalid() bool    { return true }
func (r *fakeResolver) ClearCache()      {}
func (r *fakeResolver) ResetConnection() {}

func TestAddressPortStrategy(t *testing.T) {
	r := &fakeResolver{records: []string{
		`_xray._tcp.example.org. 60 IN SRV 20 5 2000 backup.example.org.`,
		`_xray._tcp.example.org. 60 IN SRV 10 1 1000 low.example.org.`,
		`_xray._tcp.example.org. 60 IN SRV 10 9 1001 entry.example.org.`,
		`txt.example.org. 60 IN TXT "v=spf1 -all"`,
		`txt.example.org. 60 IN TXT "198.51.100.7:8443"`,
		`junk.example.org. 60 IN TXT "no address here"`,
	}}
	rewrite := func(strategy, address string) string {
		return Sockopt{AddressPortStrategy: strategy}.rewriteAddress(context.Background(), address, r)
	}

	assert.Equal(t, "entry.example.org:1001", rewrite(AddressPortSrvPortAndAddress, "_xray._tcp.example.org:443"))
	assert.Equal(t, "_xray._tcp.example.org:1001", rewrite(AddressPortSrvPortOnly, "_xray._tcp.example.org:443"))
	assert.Equal(t, "entry.example.org:443", rewrite(AddressPortSrvAddressOnly, "_xray._tcp.example.org:443"))
	assert.Equal(t, "198.51.100.7:8443", rewrite(AddressPortTxtPortAndAddress, "txt.example.org:443"))
	assert.Equal(t, "txt.example.org:8443", rewrite(AddressPortTxtPortOnly, "txt.example.org:443"))
	assert.Equal(t, "198.51.100.7:443", rewrite(AddressPortTxtAddressOnly, "txt.example.org:443"))

	// nothing to go by: the address stays as configured
	assert.Equal(t, "txt.example.org:443", rewrite(AddressPortNone, "txt.example.org:443"))
	assert.Equal(t, "192.0.2.1:443", rewrite(AddressPortTxtPortAndAddress, "192.0.2.1:443"))
	assert.Equal(t, "[2001:db8::1]:443", rewrite(AddressPortSrvPortAndAddress, "[2001:db8::1]:443"))
	assert.Equal(t, "plain.example.org:443", rewrite(AddressPortSrvPortAndAddress, "plain.example.org:443"))
	assert.Equal(t, "_none._tcp.example.org:443", rewrite(AddressPortSrvPortAndAddress, "_none._tcp.example.org:443"))
	assert.Equal(t, "junk.example.org:443", rewrite(AddressPortTxtPortAndAddress, "junk.example.org:443"))

	assert.Contains(t, r.asked, "SRV _xray._tcp.example.org.")
	assert.Contains(t, r.asked, "TXT txt.example.org.")
	assert.NotContains(t, r.asked, "SRV plain.example.org.")
}

func TestParseAddressPortStrategy(t *testing.T) {
	for in, want := range map[string]string{
		"": "", "none": "", "None": "",
		"SrvPortOnly": AddressPortSrvPortOnly, "srvaddressonly": AddressPortSrvAddressOnly, "SRVPORTANDADDRESS": AddressPortSrvPortAndAddress,
		"TxtPortOnly": AddressPortTxtPortOnly, "txtAddressOnly": AddressPortTxtAddressOnly, "txtportandaddress": AddressPortTxtPortAndAddress,
	} {
		got, err := ParseAddressPortStrategy(in)
		require.NoError(t, err, in)
		assert.Equal(t, want, got, in)
	}
	_, err := ParseAddressPortStrategy("srv")
	assert.Error(t, err)
}

// The dial goes to where the record points.
func TestDialWithAddressPortStrategy(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	_, port, _ := net.SplitHostPort(l.Addr().String())
	r := &fakeResolver{records: []string{`_xray._tcp.example.org. 60 IN SRV 0 0 ` + port + ` entry.example.org.`}}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := DialContext(ctx, "tcp", "_xray._tcp.example.org:1",
		WithResolver(r), WithSockopt(Sockopt{AddressPortStrategy: AddressPortSrvPortAndAddress}))
	require.NoError(t, err)
	defer conn.Close()
	assert.Equal(t, l.Addr().String(), conn.RemoteAddr().String())
}
