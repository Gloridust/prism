package prism

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
)

// 密码学套件 v1：X25519 + AES-256-GCM + HKDF-SHA256 + AES-256-CTR(混淆)
// 原语全部为标准库成熟实现；协议原创性在上层编排（见 docs/PROTOCOL.md）。

const (
	KeySize   = 32 // X25519 公私钥、对称密钥长度
	NonceSize = 12 // AES-GCM nonce
	TagSize   = 16 // AES-GCM tag
	SaltSize  = 16 // 握手混淆盐 / CTR IV
)

// ProtocolName 作为密码学域分隔符，初始化握手摘要。
const ProtocolName = "Prism_IKpsk_25519_AESGCM_SHA256_v1"

var curve = ecdh.X25519()

var (
	errShortRand = errors.New("prism: insufficient randomness")
)

// randBytes 返回 n 字节密码学安全随机数。
func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic(errShortRand) // crypto/rand 失败属不可恢复的系统级错误
	}
	return b
}

// --- HKDF-SHA256（RFC 5869，自实现，零外部依赖）---

func hkdfExtract(salt, ikm []byte) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	m := hmac.New(sha256.New, salt)
	m.Write(ikm)
	return m.Sum(nil)
}

func hkdfExpand(prk, info []byte, length int) []byte {
	out := make([]byte, 0, length)
	var t []byte
	var counter byte = 1
	for len(out) < length {
		m := hmac.New(sha256.New, prk)
		m.Write(t)
		m.Write(info)
		m.Write([]byte{counter})
		t = m.Sum(nil)
		out = append(out, t...)
		counter++
	}
	return out[:length]
}

// hkdf 一步完成 Extract+Expand。
func hkdf(salt, ikm, info []byte, length int) []byte {
	return hkdfExpand(hkdfExtract(salt, ikm), info, length)
}

// --- X25519 ---

// GenerateKeyPair 生成一对 X25519 密钥。
func GenerateKeyPair() (*ecdh.PrivateKey, error) {
	return curve.GenerateKey(rand.Reader)
}

// ParsePublicKey / ParsePrivateKey 从 32 字节原始值解析。
func ParsePublicKey(b []byte) (*ecdh.PublicKey, error)  { return curve.NewPublicKey(b) }
func ParsePrivateKey(b []byte) (*ecdh.PrivateKey, error) { return curve.NewPrivateKey(b) }

// dh 执行 X25519；标准库会在结果为全零（低阶点）时返回错误。
func dh(priv *ecdh.PrivateKey, pub *ecdh.PublicKey) ([]byte, error) {
	return priv.ECDH(pub)
}

// --- AEAD（AES-256-GCM）---

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// nonceFromCounter 把计数器编码为 12 字节 nonce（前 4 字节 0，后 8 字节大端）。
func nonceFromCounter(counter uint64) []byte {
	n := make([]byte, NonceSize)
	binary.BigEndian.PutUint64(n[4:], counter)
	return n
}

// --- AES-256-CTR 混淆键流 ---

func newCTR(key, iv []byte) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCTR(block, iv), nil
}

// obfuscate 用 PSK + salt 派生的 CTR 键流就地 XOR data（加解密同一操作）。
func obfuscate(psk, salt, data []byte) error {
	okey := hkdf(psk, salt, []byte("prism-obfs-key"), KeySize)
	oiv := hkdf(psk, salt, []byte("prism-obfs-iv"), SaltSize)
	ctr, err := newCTR(okey, oiv)
	if err != nil {
		return err
	}
	ctr.XORKeyStream(data, data)
	return nil
}
