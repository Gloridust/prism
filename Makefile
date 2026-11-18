# Prism build & cross-compile.
# Prereq: a build host WITH module access for the first `go` run — Prism now has
# third-party deps (uTLS, golang.org/x/crypto), so `go mod download` (or
# `go mod vendor`) them once for offline/cross builds. All deps are pure Go, so
# GOOS/GOARCH cross-compiles need no CGO. See docs/DEVELOPMENT.md.

VERSION ?= 0.2.0
LDFLAGS := -s -w -X main.version=$(VERSION)
OUT := dist

WINTUN_VERSION := 0.14.1

.PHONY: all test server client keygen clean wintun \
        client-linux-amd64 client-linux-arm64 client-linux-mipsle client-linux-mips \
        client-linux-mipsle-chacha client-linux-mips-chacha \
        client-darwin-arm64 client-darwin-amd64 client-windows-amd64 \
        server-linux-amd64 server-linux-arm64

all: test server client keygen

test:
	go test ./...

# --- native ---
server:
	go build -ldflags "$(LDFLAGS)" -o $(OUT)/prism-server ./cmd/prism-server
client:
	go build -ldflags "$(LDFLAGS)" -o $(OUT)/prism-client ./cmd/prism-client
keygen:
	go build -ldflags "$(LDFLAGS)" -o $(OUT)/prism-keygen ./cmd/prism-keygen

# --- server (Singapore box; usually linux/amd64 or arm64) ---
server-linux-amd64:
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(OUT)/prism-server-linux-amd64 ./cmd/prism-server
server-linux-arm64:
	GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(OUT)/prism-server-linux-arm64 ./cmd/prism-server

# --- client: routers (OpenWrt) ---
# Pick the one matching your router's CPU. Common: arm64 (most modern),
# mipsle (MT762x etc.), mips (older big-endian Atheros).
client-linux-arm64:
	GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(OUT)/prism-client-linux-arm64 ./cmd/prism-client
client-linux-mipsle:
	GOOS=linux GOARCH=mipsle GOMIPS=softfloat go build -ldflags "$(LDFLAGS)" -o $(OUT)/prism-client-linux-mipsle ./cmd/prism-client
client-linux-mips:
	GOOS=linux GOARCH=mips GOMIPS=softfloat go build -ldflags "$(LDFLAGS)" -o $(OUT)/prism-client-linux-mips ./cmd/prism-client

# Router firmware defaulting to ChaCha20-Poly1305 (no AES-NI) via -tags prism_chacha.
# An explicit "cipher" in client.json still overrides the compiled default.
client-linux-mipsle-chacha:
	GOOS=linux GOARCH=mipsle GOMIPS=softfloat go build -tags prism_chacha -ldflags "$(LDFLAGS)" -o $(OUT)/prism-client-linux-mipsle-chacha ./cmd/prism-client
client-linux-mips-chacha:
	GOOS=linux GOARCH=mips GOMIPS=softfloat go build -tags prism_chacha -ldflags "$(LDFLAGS)" -o $(OUT)/prism-client-linux-mips-chacha ./cmd/prism-client

# --- client: desktops (work from home) ---
client-darwin-arm64:
	GOOS=darwin GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(OUT)/prism-client-macos-arm64 ./cmd/prism-client
client-darwin-amd64:
	GOOS=darwin GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(OUT)/prism-client-macos-amd64 ./cmd/prism-client
client-windows-amd64: wintun
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(OUT)/prism-client-windows-amd64.exe ./cmd/prism-client
	cp $(OUT)/wintun/bin/amd64/wintun.dll $(OUT)/wintun.dll

# Download and extract wintun.dll (MIT-licensed, https://www.wintun.net).
# Ships alongside the Windows client binary.
wintun: $(OUT)/wintun/bin/amd64/wintun.dll

$(OUT)/wintun/bin/amd64/wintun.dll:
	@mkdir -p $(OUT)
	curl -fsSL "https://www.wintun.net/builds/wintun-$(WINTUN_VERSION).zip" -o $(OUT)/wintun.zip
	unzip -qo $(OUT)/wintun.zip -d $(OUT)
	rm $(OUT)/wintun.zip

clean:
	rm -rf $(OUT)
