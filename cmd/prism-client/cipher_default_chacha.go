//go:build prism_chacha

package main

import "github.com/gloridust/prism/pkg/prism"

// defaultCipher is ChaCha20-Poly1305 in a -tags prism_chacha build, so router
// firmware on hardware without AES-NI defaults to the faster, constant-time
// cipher without a per-device config edit. An explicit "cipher" in the config
// always overrides this default.
const defaultCipher = prism.CipherChaCha20Poly1305
