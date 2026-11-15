package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPanelCSRF(t *testing.T) {
	a := &app{cfg: &ClientConfig{Server: "x", Mode: "router"}} // router mode: Connect/Disconnect are no-ops, safe to call
	h := a.panelMux()

	call := func(method, origin string) int {
		req := httptest.NewRequest(method, "http://127.0.0.1:9797/api/disconnect", nil)
		req.Host = "127.0.0.1:9797"
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr.Code
	}

	if got := call("GET", ""); got != http.StatusForbidden {
		t.Errorf("GET should be forbidden, got %d", got)
	}
	if got := call("POST", "http://evil.example.com"); got != http.StatusForbidden {
		t.Errorf("cross-origin POST should be forbidden, got %d", got)
	}
	if got := call("POST", "http://127.0.0.1:9797"); got == http.StatusForbidden {
		t.Errorf("same-origin POST should be allowed, got %d", got)
	}
	if got := call("POST", ""); got == http.StatusForbidden {
		t.Errorf("no-Origin POST (local tooling) should be allowed, got %d", got)
	}
}
