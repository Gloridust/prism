//go:build !prism_chacha

package main

import "github.com/gloridust/prism/pkg/prism"

// defaultCipher is the carrier AEAD used when the client config leaves "cipher"
// unset. The default build uses AES-256-GCM. Build the client with
//
//	go build -tags prism_chacha ./cmd/prism-client
//
// to default to ChaCha20-Poly1305 instead — handy for router firmware images on
// MIPS / older ARM (no AES-NI) where you'd rather not ship a per-device config
// edit. An explicit "cipher" in the config always overrides this default.
const defaultCipher = prism.CipherAES256GCM
