# Prism build & cross-compile.
# Prereq on a build host WITH network for the first `go` run (stdlib only, so
# no third-party downloads are actually needed).

VERSION ?= 0.1.0
LDFLAGS := -s -w -X main.version=$(VERSION)
OUT := dist

.PHONY: all test server client keygen clean \
        client-linux-amd64 client-linux-arm64 client-linux-mipsle client-linux-mips \
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

# --- client: desktops (work from home) ---
client-darwin-arm64:
	GOOS=darwin GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(OUT)/prism-client-macos-arm64 ./cmd/prism-client
client-darwin-amd64:
	GOOS=darwin GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(OUT)/prism-client-macos-amd64 ./cmd/prism-client
client-windows-amd64:
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(OUT)/prism-client-windows-amd64.exe ./cmd/prism-client

clean:
	rm -rf $(OUT)
