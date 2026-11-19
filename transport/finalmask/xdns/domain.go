package xdns

import (
	"encoding/base32"
	"errors"
	"fmt"
	"sort"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/idna"
)

// The name of a query is base32 text without padding, lower case, cut into
// labels, followed by the domain.
var base32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// typeCodes are the record types a tunnel may use and the two bits that name
// the type in the first byte of every query.
var typeCodes = map[dnsmessage.Type]byte{
	dnsmessage.TypeA:     0,
	dnsmessage.TypeCNAME: 1,
	dnsmessage.TypeTXT:   2,
	dnsmessage.TypeAAAA:  3,
}

// domain is one name the tunnel server is authoritative for.
type domain struct {
	name       dnsmessage.Name
	labelLimit int
	types      []dnsmessage.Type
	edns0      uint16 // UDP payload size announced in the queries, 0 for no EDNS

	// cap is how many bytes fit into one query name.
	cap int
}

// newDomain checks the settings of a domain. lenLimit bounds the query name
// as it is on the wire, labelLimit the labels that carry data.
func newDomain(name string, lenLimit, labelLimit int, types []int, edns0 int) (*domain, error) {
	if strings.Contains(name, "..") {
		return nil, errors.New("invalid domain")
	}
	if lenLimit < 0 || lenLimit > 255 {
		return nil, errors.New("len-limit must be within 0-255")
	}
	if labelLimit < 0 || labelLimit > 63 {
		return nil, errors.New("label-limit must be within 0-63")
	}
	if lenLimit == 0 {
		lenLimit = 255
	}
	if labelLimit == 0 {
		labelLimit = 63
	}
	if len(types) == 0 {
		types = []int{int(dnsmessage.TypeTXT)}
	}
	d := &domain{labelLimit: labelLimit, edns0: uint16(edns0)}
	for _, t := range types {
		if _, ok := typeCodes[dnsmessage.Type(t)]; !ok || t < 0 || t > 0xFFFF {
			return nil, fmt.Errorf("unknown record type %d, want 1 (A), 5 (CNAME), 16 (TXT) or 28 (AAAA)", t)
		}
		d.types = append(d.types, dnsmessage.Type(t))
	}
	if edns0 != 0 && (edns0 < 512 || edns0 > 4096) {
		return nil, errors.New("edns0 must be 0 or within 512-4096")
	}
	// The name has to be a valid internationalized one, but it goes out as
	// it is written: this is what the server does with its own setting.
	if _, err := idna.ToASCII(name); err != nil {
		return nil, err
	}
	var err error
	if d.name, err = dnsmessage.NewName(name + "."); err != nil {
		return nil, err
	}

	// What the domain leaves of the name is filled with labels of labelLimit
	// characters, each costing one more byte on the wire.
	room := lenLimit - int(d.name.Length) - 1
	if room < 0 {
		return nil, errors.New("len-limit is shorter than the domain")
	}
	chars := room / (labelLimit + 1) * labelLimit
	if left := room % (labelLimit + 1); left > 1 {
		chars += left - 1
	}
	d.cap = base32Encoding.DecodedLen(chars)
	if d.cap < 17 {
		return nil, fmt.Errorf("a query name carries %d bytes, need at least 17: the domain is too long for len-limit and label-limit", d.cap)
	}
	// The longest query has to be a valid DNS message.
	if _, err := d.query(d.encode(make([]byte, d.cap)), d.types[0], nil); err != nil {
		return nil, fmt.Errorf("invalid domain: %w", err)
	}
	return d, nil
}

// fragmentCap is how many bytes of a datagram fit into a query that carries
// one piece of it.
func (d *domain) fragmentCap() int {
	return d.cap - queryHeader - fragmentHeader
}

// limit is the largest datagram the domain carries: it is split over
// maxFragments queries at most.
func (d *domain) limit() int {
	if limit := maxFragments * d.fragmentCap(); limit < maxDatagram {
		return limit
	}
	return maxDatagram
}

// contains tells whether name ends with the domain.
func (d *domain) contains(name dnsmessage.Name) bool {
	if d.name.Length >= name.Length {
		return false
	}
	return equalFold(d.name.Data[:d.name.Length], name.Data[name.Length-d.name.Length:name.Length])
}

// equalFold tells whether two names differ in the case of letters at most.
func equalFold(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if lower(a[i]) != lower(b[i]) {
			return false
		}
	}
	return true
}

func sameName(a, b dnsmessage.Name) bool {
	return equalFold(a.Data[:a.Length], b.Data[:b.Length])
}

// lower folds the case of an ASCII letter, the only case DNS knows.
func lower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

func (d *domain) hasType(t dnsmessage.Type) bool {
	for _, own := range d.types {
		if own == t {
			return true
		}
	}
	return false
}

// encode returns the name that carries data, at most cap bytes.
func (d *domain) encode(data []byte) dnsmessage.Name {
	var encoded [256]byte
	text := encoded[:base32Encoding.EncodedLen(len(data))]
	base32Encoding.Encode(text, data)
	var name dnsmessage.Name
	b := name.Data[:0]
	for i, c := range text {
		if i > 0 && i%d.labelLimit == 0 {
			b = append(b, '.')
		}
		b = append(b, lower(c))
	}
	if len(text) > 0 {
		b = append(b, '.')
	}
	b = append(b, d.name.Data[:d.name.Length]...)
	name.Length = uint8(len(b))
	return name
}

// decode returns the bytes a name under the domain carries, nil when it
// carries none.
func (d *domain) decode(name dnsmessage.Name) []byte {
	if !d.contains(name) {
		return nil
	}
	var text []byte
	for _, c := range name.Data[:name.Length-d.name.Length] {
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		if c != '.' {
			text = append(text, c)
		}
	}
	data := make([]byte, base32Encoding.DecodedLen(len(text)))
	n, err := base32Encoding.Decode(data, text)
	if err != nil {
		return nil
	}
	return data[:n]
}

// query appends to buf the DNS query of type qtype for a name made by encode.
// The caller sets the message ID.
func (d *domain) query(name dnsmessage.Name, qtype dnsmessage.Type, buf []byte) ([]byte, error) {
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name:  name,
			Type:  qtype,
			Class: dnsmessage.ClassINET,
		}},
	}
	if d.edns0 > 0 {
		msg.Additionals = []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{
				Name:  dnsmessage.MustNewName("."),
				Type:  dnsmessage.TypeOPT,
				Class: dnsmessage.Class(d.edns0),
			},
			Body: &dnsmessage.OPTResource{},
		}}
	}
	return msg.AppendPack(buf)
}

// payload returns what the answers of a response to a query under the domain
// carry: the datagrams of the server, each behind its length. The records
// that count are those of the name and the type that were asked for.
func (d *domain) payload(msg *dnsmessage.Message) []byte {
	question := msg.Questions[0]
	qtype := question.Type
	if qtype == dnsmessage.TypeTXT {
		// one record, the data is its strings put together
		if len(msg.Answers) != 1 || !sameName(msg.Answers[0].Header.Name, question.Name) {
			return nil
		}
		txt, ok := msg.Answers[0].Body.(*dnsmessage.TXTResource)
		if !ok {
			return nil
		}
		return []byte(strings.Join(txt.TXT, ""))
	}

	// The other types spread the data over several records, in any order.
	// Each starts with its index; in the first one the number of records
	// follows. All of them have to be there, once.
	var pieces [][]byte
	for i := range msg.Answers {
		answer := &msg.Answers[i]
		if !sameName(answer.Header.Name, question.Name) || answer.Header.Type != qtype {
			continue
		}
		switch body := answer.Body.(type) {
		case *dnsmessage.AResource:
			pieces = append(pieces, body.A[:])
		case *dnsmessage.AAAAResource:
			pieces = append(pieces, body.AAAA[:])
		case *dnsmessage.CNAMEResource:
			if piece := d.decode(body.CNAME); len(piece) > 0 {
				pieces = append(pieces, piece)
			}
		}
	}
	sort.Slice(pieces, func(i, j int) bool { return pieces[i][0] < pieces[j][0] })
	if len(pieces) == 0 || len(pieces[0]) < 2 || pieces[0][0] != 0 || int(pieces[0][1]) != len(pieces) {
		return nil
	}
	data := append([]byte(nil), pieces[0][2:]...)
	for i := 1; i < len(pieces); i++ {
		if int(pieces[i][0]) != i {
			return nil
		}
		data = append(data, pieces[i][1:]...)
	}
	return data
}

// splitDatagrams cuts the payload of a response into the datagrams of the
// server. Each has a two byte length in front; the two top bits are set on
// the last one, what follows it is padding. A payload that does not end with
// such a datagram is dropped as a whole.
func splitDatagrams(payload []byte) [][]byte {
	var datagrams [][]byte
	for len(payload) > 1 {
		last := payload[0]&0xC0 == 0xC0
		length := int(payload[0]&0x3F)<<8 | int(payload[1])
		payload = payload[2:]
		if length > len(payload) {
			return nil
		}
		datagrams = append(datagrams, append([]byte(nil), payload[:length]...))
		if last {
			return datagrams
		}
		payload = payload[length:]
	}
	return nil
}
