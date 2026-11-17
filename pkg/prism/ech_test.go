package prism

import (
	"encoding/binary"
	"testing"
)

func TestParseSVCBForECH(t *testing.T) {
	echPayload := []byte{0xfe, 0x0d, 0x00, 0x10, 0x01, 0x02, 0x03, 0x04}

	// Build SVCB RDATA: priority=1, target=".", SvcParam key=5 (ech).
	var rdata []byte
	rdata = binary.BigEndian.AppendUint16(rdata, 1) // priority
	rdata = append(rdata, 0)                         // root label (target ".")
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
	rdata = append(rdata, 0) // root target
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
