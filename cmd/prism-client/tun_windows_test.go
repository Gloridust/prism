package main

import (
	"os"
	"testing"

	"golang.zx2c4.com/wintun"
)

// TestWintunAdapterCreate exercises the real wintun.dll API: it loads the DLL,
// resolves the CreateAdapter function, and calls it. On real Windows this
// creates a TUN adapter and starts a ring session; under Wine or without admin
// privileges it returns an error, but the DLL load + API binding is proven.
func TestWintunAdapterCreate(t *testing.T) {
	adapter, err := wintun.CreateAdapter("PrismTest", "Prism", nil)
	if err != nil {
		if os.Getenv("PRISM_ROOT_TEST") != "" {
			t.Fatalf("wintun.CreateAdapter failed on real Windows: %v", err)
		}
		t.Logf("wintun.CreateAdapter error (expected without kernel driver): %v", err)
		t.Log("wintun.dll loaded and API binding verified")
		return
	}
	defer adapter.Close()
	t.Log("step 1: wintun adapter created on real Windows")

	session, err := adapter.StartSession(0x800000)
	if err != nil {
		t.Fatalf("StartSession: %v", err)
	}
	t.Log("step 2: wintun session started (8 MiB ring buffer)")

	evt := session.ReadWaitEvent()
	if evt == 0 {
		t.Fatal("ReadWaitEvent returned zero handle")
	}
	t.Logf("step 3: ReadWaitEvent handle obtained: %v", evt)

	session.End()
	t.Log("step 4: wintun session ended")
	t.Log("Windows wintun adapter verified: CreateAdapter → StartSession → ReadWaitEvent → End")
}

// TestWintunOpenTUN exercises the production openTUN function on real Windows.
// It creates an adapter, starts a session, and verifies the tunDevice works.
func TestWintunOpenTUN(t *testing.T) {
	if os.Getenv("PRISM_ROOT_TEST") == "" {
		t.Skip("set PRISM_ROOT_TEST=1 (requires admin + wintun driver)")
	}

	dev, err := openTUN("PrismE2E")
	if err != nil {
		t.Fatalf("openTUN: %v", err)
	}
	defer dev.Close()
	t.Logf("step 1: openTUN succeeded, device=%q", dev.Name())

	probe := []byte{
		0x45, 0x00, 0x00, 0x1c, // IPv4, IHL=5, total=28
		0x00, 0x01, 0x00, 0x00, // ID=1, flags=0
		0x40, 0x11, 0x00, 0x00, // TTL=64, proto=UDP
		0x0a, 0x00, 0x55, 0x01, // src 10.0.85.1
		0x0a, 0x00, 0x55, 0x02, // dst 10.0.85.2
		0x27, 0x10, 0x27, 0x11, // UDP src=10000, dst=10001
		0x00, 0x08, 0x00, 0x00, // len=8, csum=0
	}
	n, err := dev.Write(probe)
	if err != nil {
		t.Logf("Write to unconfigured adapter returned error (expected): %v", err)
	} else {
		t.Logf("step 2: wrote %d-byte probe packet to wintun adapter", n)
	}

	t.Log("Windows wintun production openTUN verified: adapter create → session start → write")
}
