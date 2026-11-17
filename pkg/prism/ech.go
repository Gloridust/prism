package prism

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	dnsTypeHTTPS   = dnsmessage.Type(65)
	svcParamKeyECH = 5
)

// FetchECHConfigList resolves HTTPS DNS records for the given name via
// DNS-over-HTTPS and returns the ECH config list (SvcParam key 5).
// Returns nil, nil when the domain publishes no ECH config.
func FetchECHConfigList(ctx context.Context, name, dohURL string) ([]byte, error) {
	if dohURL == "" {
		dohURL = "https://1.1.1.1/dns-query"
	}

	n, err := dnsmessage.NewName(name + ".")
	if err != nil {
		return nil, fmt.Errorf("ech: invalid name %q: %w", name, err)
	}
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: n, Type: dnsTypeHTTPS, Class: dnsmessage.ClassINET}},
	}
	wire, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("ech: pack query: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", dohURL, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("ech: doh: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if err != nil {
		return nil, fmt.Errorf("ech: read: %w", err)
	}

	var p dnsmessage.Parser
	if _, err := p.Start(body); err != nil {
		return nil, fmt.Errorf("ech: parse: %w", err)
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, fmt.Errorf("ech: skip questions: %w", err)
	}
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("ech: answer: %w", err)
		}
		if h.Type != dnsTypeHTTPS {
			if err := p.SkipAnswer(); err != nil {
				return nil, err
			}
			continue
		}
		r, err := p.UnknownResource()
		if err != nil {
			return nil, fmt.Errorf("ech: rdata: %w", err)
		}
		if ech := ParseSVCBForECH(r.Data); ech != nil {
			return ech, nil
		}
	}
	return nil, nil
}

// ParseSVCBForECH extracts the ECH config list (SvcParam key 5) from
// SVCB/HTTPS RDATA. Returns nil when the param is absent.
func ParseSVCBForECH(rdata []byte) []byte {
	if len(rdata) < 3 {
		return nil
	}
	priority := binary.BigEndian.Uint16(rdata[:2])
	if priority == 0 {
		return nil // AliasMode — no SvcParams
	}
	// Skip wire-format DNS TargetName.
	off := 2
	for off < len(rdata) {
		if rdata[off] == 0 {
			off++
			break
		}
		if rdata[off]&0xc0 == 0xc0 {
			off += 2
			break
		}
		off += 1 + int(rdata[off])
	}
	for off+4 <= len(rdata) {
		key := binary.BigEndian.Uint16(rdata[off:])
		vlen := int(binary.BigEndian.Uint16(rdata[off+2:]))
		off += 4
		if off+vlen > len(rdata) {
			break
		}
		if key == svcParamKeyECH {
			out := make([]byte, vlen)
			copy(out, rdata[off:off+vlen])
			return out
		}
		off += vlen
	}
	return nil
}
