package dialer

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/randv2"
	D "github.com/miekg/dns"
)

// The address port strategies of Xray-core (sockopt.addressPortStrategy): the
// address and the port to dial are taken from a DNS record of the configured
// server name, so that a blocked address or port is replaced by changing one
// record. Either a SRV record, for a name like _service._proto.example.org, or
// a TXT record holding "host:port".
const (
	AddressPortNone              = ""
	AddressPortSrvPortOnly       = "srvportonly"
	AddressPortSrvAddressOnly    = "srvaddressonly"
	AddressPortSrvPortAndAddress = "srvportandaddress"
	AddressPortTxtPortOnly       = "txtportonly"
	AddressPortTxtAddressOnly    = "txtaddressonly"
	AddressPortTxtPortAndAddress = "txtportandaddress"
)

// ParseAddressPortStrategy reads the names Xray-core takes, in any case.
func ParseAddressPortStrategy(s string) (string, error) {
	switch s = strings.ToLower(s); s {
	case "", "none":
		return AddressPortNone, nil
	case AddressPortSrvPortOnly, AddressPortSrvAddressOnly, AddressPortSrvPortAndAddress,
		AddressPortTxtPortOnly, AddressPortTxtAddressOnly, AddressPortTxtPortAndAddress:
		return s, nil
	}
	return "", errors.New("unsupported address and port strategy: " + s)
}

// rewriteAddress applies the strategy to the address to dial. Like Xray-core
// it leaves an IP address alone and falls back to the address as configured
// when the record cannot be had.
func (s Sockopt) rewriteAddress(ctx context.Context, address string, r resolver.Resolver) string {
	if s.AddressPortStrategy == AddressPortNone {
		return address
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return address
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return address
	}
	bySrv := strings.HasPrefix(s.AddressPortStrategy, "srv")
	lookup := lookupTXTAddress
	if bySrv {
		lookup = lookupSRVAddress
	}
	newHost, newPort, err := lookup(ctx, host, r)
	if err != nil {
		log.Debugln("[Dialer] address port strategy %s for %s: %v", s.AddressPortStrategy, host, err)
		return address
	}
	switch s.AddressPortStrategy {
	case AddressPortSrvPortOnly, AddressPortTxtPortOnly:
		newHost = host
	case AddressPortSrvAddressOnly, AddressPortTxtAddressOnly:
		newPort = port
	}
	log.Debugln("[Dialer] address port strategy %s: %s -> %s", s.AddressPortStrategy, address, net.JoinHostPort(newHost, newPort))
	return net.JoinHostPort(newHost, newPort)
}

// dnsAnswers asks the resolver of the proxy servers, or nil when there is none.
func dnsAnswers(ctx context.Context, name string, qtype uint16, r resolver.Resolver) ([]D.RR, bool, error) {
	if r == nil {
		r = resolver.ProxyServerHostResolver
	}
	if r == nil || !r.Invalid() { // Invalid reports a usable resolver
		return nil, false, nil
	}
	query := &D.Msg{}
	query.SetQuestion(D.Fqdn(name), qtype)
	msg, err := r.ExchangeContext(ctx, query)
	if err != nil {
		return nil, true, err
	}
	return msg.Answer, true, nil
}

// lookupSRVAddress returns the target and the port of a SRV record of a name
// like _service._proto.example.org.
func lookupSRVAddress(ctx context.Context, name string, r resolver.Resolver) (string, string, error) {
	parts := strings.SplitN(name, ".", 3)
	if len(parts) != 3 || !strings.HasPrefix(parts[0], "_") || !strings.HasPrefix(parts[1], "_") {
		return "", "", errors.New("not a _service._proto.name address")
	}
	answers, asked, err := dnsAnswers(ctx, name, D.TypeSRV, r)
	if err != nil {
		return "", "", err
	}
	if !asked {
		_, records, err := net.DefaultResolver.LookupSRV(ctx, parts[0][1:], parts[1][1:], parts[2])
		if err != nil {
			return "", "", err
		}
		if len(records) == 0 {
			return "", "", errors.New("no SRV record")
		}
		return strings.TrimSuffix(records[0].Target, "."), strconv.Itoa(int(records[0].Port)), nil
	}
	var records []*D.SRV
	for _, rr := range answers {
		if srv, ok := rr.(*D.SRV); ok {
			records = append(records, srv)
		}
	}
	best := pickSRV(records)
	if best == nil {
		return "", "", errors.New("no SRV record")
	}
	return strings.TrimSuffix(best.Target, "."), strconv.Itoa(int(best.Port)), nil
}

// pickSRV takes a record of the lowest priority, at random in proportion to
// the weights, as RFC 2782 has it and net.LookupSRV orders its result.
func pickSRV(records []*D.SRV) *D.SRV {
	var lowest []*D.SRV
	total := 0
	for _, srv := range records {
		switch {
		case len(lowest) == 0 || srv.Priority < lowest[0].Priority:
			lowest, total = []*D.SRV{srv}, int(srv.Weight)
		case srv.Priority == lowest[0].Priority:
			lowest, total = append(lowest, srv), total+int(srv.Weight)
		}
	}
	if len(lowest) == 0 {
		return nil
	}
	if total == 0 {
		return lowest[randv2.IntN(len(lowest))]
	}
	n := randv2.IntN(total)
	for _, srv := range lowest {
		if n -= int(srv.Weight); n < 0 {
			return srv
		}
	}
	return lowest[len(lowest)-1]
}

// lookupTXTAddress returns the first "host:port" among the TXT records of name.
func lookupTXTAddress(ctx context.Context, name string, r resolver.Resolver) (string, string, error) {
	answers, asked, err := dnsAnswers(ctx, name, D.TypeTXT, r)
	if err != nil {
		return "", "", err
	}
	var records []string
	if asked {
		for _, rr := range answers {
			if txt, ok := rr.(*D.TXT); ok {
				records = append(records, strings.Join(txt.Txt, ""))
			}
		}
	} else if records, err = net.DefaultResolver.LookupTXT(ctx, name); err != nil {
		return "", "", err
	}
	for _, record := range records {
		host, port, err := net.SplitHostPort(strings.TrimSpace(record))
		if err != nil || host == "" {
			continue
		}
		if n, err := strconv.ParseUint(port, 10, 16); err != nil || n == 0 {
			continue
		}
		return host, port, nil
	}
	return "", "", errors.New("no host:port TXT record")
}
