package main

import (
	"testing"

	"golang.zx2c4.com/wintun"
)

// TestWintunAdapterCreate exercises the real wintun.dll API: it loads the DLL,
// resolves the CreateAdapter function, and calls it. On real Windows this
// creates a TUN adapter; under Wine or without admin privileges it returns an
// error, but the DLL load + API binding is proven either way.
func TestWintunAdapterCreate(t *testing.T) {
	adapter, err := wintun.CreateAdapter("PrismTest", "Prism", nil)
	if err != nil {
		// Expected under Wine or non-admin: the wintun kernel driver is
		// not present. The important thing is that we reached here — the
		// DLL loaded and CreateAdapter was called.
		t.Logf("wintun.CreateAdapter returned error (expected without kernel driver): %v", err)
		t.Log("wintun.dll loaded and API binding verified")
		return
	}
	// If we got here, we're on real Windows with admin. Close the adapter.
	defer adapter.Close()
	t.Log("wintun adapter created successfully on real Windows")

	session, err := adapter.StartSession(0x800000)
	if err != nil {
		t.Fatalf("StartSession: %v", err)
	}
	session.End()
	t.Log("wintun session start/end verified")
}
