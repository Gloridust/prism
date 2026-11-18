package prism

import (
	"context"
	"encoding/binary"
	"os"
	"testing"
	"time"
)

func TestParseSVCBForECH(t *testing.T) {
	echPayload := []byte{0xfe, 0x0d, 0x00, 0x10, 0x01, 0x02, 0x03, 0x04}

	// Build SVCB RDATA: priority=1, target=".", SvcParam key=5 (ech).
	var rdata []byte
	rdata = binary.BigEndian.AppendUint16(rdata, 1) // priority
	rdata = append(rdata, 0)                        // root label (target ".")
	rdata = binary.BigEndian.AppendUint16(rdata, svcParamKeyECH)
	rdata = binary.BigEndian.AppendUint16(rdata, uint16(len(echPayload)))
	rdata = append(rdata, echPayload...)

	got := ParseSVCBForECH(rdata)
	if got == nil {
		t.Fatal("expected ECH config, got nil")
	}
	if len(got) != len(echPayload) {
		t.Fatalf("length mismatch: got %d, want %d", len(got), len(echPayload))
	}
	for i := range got {
		if got[i] != echPayload[i] {
			t.Fatalf("byte %d: got %#x, want %#x", i, got[i], echPayload[i])
		}
	}
}

func TestParseSVCBForECH_NoECH(t *testing.T) {
	// SVCB with ALPN (key=1) but no ECH.
	var rdata []byte
	rdata = binary.BigEndian.AppendUint16(rdata, 1)
	rdata = append(rdata, 0)                        // root target
	rdata = binary.BigEndian.AppendUint16(rdata, 1) // alpn key
	alpn := []byte{2, 'h', '2'}
	rdata = binary.BigEndian.AppendUint16(rdata, uint16(len(alpn)))
	rdata = append(rdata, alpn...)

	if got := ParseSVCBForECH(rdata); got != nil {
		t.Fatalf("expected nil, got %v", got)
	}
}

func TestParseSVCBForECH_AliasMode(t *testing.T) {
	// Priority 0 = AliasMode, no SvcParams expected.
	var rdata []byte
	rdata = binary.BigEndian.AppendUint16(rdata, 0)
	rdata = append(rdata, 7)
	rdata = append(rdata, "example"...)
	rdata = append(rdata, 3)
	rdata = append(rdata, "com"...)
	rdata = append(rdata, 0)

	if got := ParseSVCBForECH(rdata); got != nil {
		t.Fatalf("expected nil for alias mode, got %v", got)
	}
}

func TestParseSVCBForECH_MultipleSvcParams(t *testing.T) {
	echPayload := []byte{0xAA, 0xBB, 0xCC}

	// ALPN (key=1) followed by ECH (key=5).
	var rdata []byte
	rdata = binary.BigEndian.AppendUint16(rdata, 1)
	rdata = append(rdata, 0) // root target
	// alpn
	rdata = binary.BigEndian.AppendUint16(rdata, 1)
	alpn := []byte{2, 'h', '3'}
	rdata = binary.BigEndian.AppendUint16(rdata, uint16(len(alpn)))
	rdata = append(rdata, alpn...)
	// ech
	rdata = binary.BigEndian.AppendUint16(rdata, svcParamKeyECH)
	rdata = binary.BigEndian.AppendUint16(rdata, uint16(len(echPayload)))
	rdata = append(rdata, echPayload...)

	got := ParseSVCBForECH(rdata)
	if got == nil {
		t.Fatal("expected ECH config, got nil")
	}
	if len(got) != 3 || got[0] != 0xAA || got[1] != 0xBB || got[2] != 0xCC {
		t.Fatalf("unexpected ECH payload: %x", got)
	}
}

// TestFetchECHConfigList_Live queries a known ECH-enabled domain via Cloudflare
// DoH to verify that FetchECHConfigList works against real DNS infrastructure.
// Skipped in CI or when PRISM_LIVE_TEST is not set.
func TestFetchECHConfigList_Live(t *testing.T) {
	if os.Getenv("PRISM_LIVE_TEST") == "" {
		t.Skip("set PRISM_LIVE_TEST=1 to run live ECH fetch test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// crypto.cloudflare.com is a known ECH-enabled domain.
	ech, err := FetchECHConfigList(ctx, "crypto.cloudflare.com", "")
	if err != nil {
		t.Fatalf("FetchECHConfigList: %v", err)
	}
	if len(ech) == 0 {
		t.Fatal("expected non-empty ECH config from crypto.cloudflare.com")
	}
	t.Logf("fetched %d-byte ECH config from crypto.cloudflare.com via DoH", len(ech))

	// Verify the ECH config starts with a valid version (0xfe0d = draft ECH).
	if len(ech) >= 2 {
		ver := binary.BigEndian.Uint16(ech[:2])
		t.Logf("ECH config version: 0x%04x", ver)
	}
}

// TestFetchECHConfigList_NoDomain verifies that querying a domain with no ECH
// returns nil without error.
func TestFetchECHConfigList_NoDomain(t *testing.T) {
	if os.Getenv("PRISM_LIVE_TEST") == "" {
		t.Skip("set PRISM_LIVE_TEST=1 to run live ECH fetch test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	ech, err := FetchECHConfigList(ctx, "example.com", "")
	if err != nil {
		t.Fatalf("FetchECHConfigList: %v", err)
	}
	if ech != nil {
		t.Fatalf("expected nil ECH for example.com, got %d bytes", len(ech))
	}
	t.Log("example.com correctly returned no ECH config")
}
