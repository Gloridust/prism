package prism

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"time"
)

// 握手 wire 常量（见 docs/PROTOCOL.md §4、§10）
const (
	msg1Len          = SaltSize + 32 + 48 + 48 // 144：salt + E_pub + encStatic + encPayload
	msg2Len          = SaltSize + 32 + 48       // 96 ：salt + F_pub + encPayload2
	payload1PlainLen = 32
	payload2PlainLen = 32
	versionV1        = 0x01
	handshakeWindow  = 90 // 秒；|now-ts| 超过即拒
)

var (
	errAuth        = errors.New("prism: handshake authentication failed")
	errVersion     = errors.New("prism: unsupported protocol version")
	errHandshakeIO = errors.New("prism: handshake short read")
)

// HandshakeResult 握手产物。
type HandshakeResult struct {
	TxKey      []byte // 本端发送方向密钥
	RxKey      []byte // 本端接收方向密钥
	SessionID  []byte // 最终握手摘要 h
	PeerStatic []byte // 对端静态公钥（服务器侧 = 客户端身份）
}

// --- 握手对称状态机（MixKey/MixHash 构造，见 §3.1）---

type symState struct {
	ck []byte
	h  []byte
	k  []byte
	n  uint64
}

func newSymState() *symState {
	sum := sha256.Sum256([]byte(ProtocolName))
	return &symState{
		ck: append([]byte(nil), sum[:]...),
		h:  append([]byte(nil), sum[:]...),
	}
}

func (s *symState) mixHash(data []byte) {
	hh := sha256.New()
	hh.Write(s.h)
	hh.Write(data)
	s.h = hh.Sum(nil)
}

func (s *symState) mixKey(ikm []byte) {
	out := hkdf(s.ck, ikm, []byte("prism-mix"), 64)
	s.ck = out[:32]
	s.k = out[32:64]
	s.n = 0
}

func (s *symState) encryptAndHash(pt []byte) ([]byte, error) {
	aead, err := newAEAD(s.k)
	if err != nil {
		return nil, err
	}
	ct := aead.Seal(nil, nonceFromCounter(s.n), pt, s.h)
	s.n++
	s.mixHash(ct)
	return ct, nil
}

func (s *symState) decryptAndHash(ct []byte) ([]byte, error) {
	aead, err := newAEAD(s.k)
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, nonceFromCounter(s.n), ct, s.h)
	if err != nil {
		return nil, err
	}
	s.n++
	s.mixHash(ct)
	return pt, nil
}

func (s *symState) split() (k1, k2 []byte) {
	out := hkdf(s.ck, nil, []byte("prism-split"), 64)
	return out[:32], out[32:64]
}

func absInt64(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

// ClientHandshake 以发起方身份完成 PHS。
func ClientHandshake(rw io.ReadWriter, psk []byte, serverPub *ecdh.PublicKey, clientPriv *ecdh.PrivateKey) (*HandshakeResult, error) {
	ss := newSymState()
	ss.mixHash(psk)
	ss.mixHash(serverPub.Bytes())

	// -> e
	eph, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	ePub := eph.PublicKey().Bytes()
	ss.mixHash(ePub)
	// es
	es, err := dh(eph, serverPub)
	if err != nil {
		return nil, err
	}
	ss.mixKey(es)
	// s
	encStatic, err := ss.encryptAndHash(clientPriv.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}
	// ss
	sss, err := dh(clientPriv, serverPub)
	if err != nil {
		return nil, err
	}
	ss.mixKey(sss)
	// payload1
	p1 := make([]byte, payload1PlainLen)
	p1[0] = versionV1
	binary.BigEndian.PutUint64(p1[1:9], uint64(time.Now().Unix()))
	p1[9] = 0 // flags：0-RTT 关
	copy(p1[10:], randBytes(payload1PlainLen-10))
	encPayload, err := ss.encryptAndHash(p1)
	if err != nil {
		return nil, err
	}

	body := make([]byte, 0, 128)
	body = append(body, ePub...)
	body = append(body, encStatic...)
	body = append(body, encPayload...)

	salt := randBytes(SaltSize)
	if err := obfuscate(psk, salt, body); err != nil {
		return nil, err
	}
	msg1 := make([]byte, 0, msg1Len)
	msg1 = append(msg1, salt...)
	msg1 = append(msg1, body...)
	if _, err := rw.Write(msg1); err != nil {
		return nil, err
	}

	// <- message 2
	msg2 := make([]byte, msg2Len)
	if _, err := io.ReadFull(rw, msg2); err != nil {
		return nil, err
	}
	salt2 := msg2[:SaltSize]
	body2 := msg2[SaltSize:]
	if err := obfuscate(psk, salt2, body2); err != nil {
		return nil, err
	}
	fPub := body2[:32]
	encP2 := body2[32:80]
	fPubKey, err := ParsePublicKey(fPub)
	if err != nil {
		return nil, err
	}
	ss.mixHash(fPub)
	// ee
	ee, err := dh(eph, fPubKey)
	if err != nil {
		return nil, err
	}
	ss.mixKey(ee)
	// se = DH(client static, server ephemeral)
	se, err := dh(clientPriv, fPubKey)
	if err != nil {
		return nil, err
	}
	ss.mixKey(se)
	p2, err := ss.decryptAndHash(encP2)
	if err != nil {
		return nil, err
	}
	if p2[0] != versionV1 {
		return nil, errVersion
	}

	k1, k2 := ss.split()
	return &HandshakeResult{
		TxKey:      k1, // client -> server
		RxKey:      k2, // server -> client
		SessionID:  ss.h,
		PeerStatic: serverPub.Bytes(),
	}, nil
}

// ServerHandshake 以响应方身份完成 PHS。
// 返回的 raw 为已从对端读取的原始字节，供认证失败时的诱饵(decoy)拼接使用。
func ServerHandshake(rw io.ReadWriter, psk []byte, serverPriv *ecdh.PrivateKey, allowed func([]byte) bool, replay *ReplayCache) (res *HandshakeResult, raw []byte, err error) {
	buf := make([]byte, msg1Len)
	n, rerr := io.ReadFull(rw, buf)
	raw = buf[:n]
	if rerr != nil {
		return nil, raw, errHandshakeIO
	}

	// 复制一份用于去混淆，保留 raw 原样供诱饵回放
	work := append([]byte(nil), buf...)
	salt := work[:SaltSize]
	body := work[SaltSize:]
	if err := obfuscate(psk, salt, body); err != nil {
		return nil, raw, err
	}
	ePub := body[:32]
	encStatic := body[32:80]
	encPayload := body[80:128]

	ss := newSymState()
	ss.mixHash(psk)
	ss.mixHash(serverPriv.PublicKey().Bytes())

	ePubKey, err := ParsePublicKey(ePub)
	if err != nil {
		return nil, raw, errAuth
	}
	ss.mixHash(ePub)
	es, err := dh(serverPriv, ePubKey)
	if err != nil {
		return nil, raw, errAuth
	}
	ss.mixKey(es)
	cPubBytes, err := ss.decryptAndHash(encStatic)
	if err != nil {
		return nil, raw, errAuth
	}
	cPubKey, err := ParsePublicKey(cPubBytes)
	if err != nil {
		return nil, raw, errAuth
	}
	sss, err := dh(serverPriv, cPubKey)
	if err != nil {
		return nil, raw, errAuth
	}
	ss.mixKey(sss)
	p1, err := ss.decryptAndHash(encPayload)
	if err != nil {
		return nil, raw, errAuth
	}
	if p1[0] != versionV1 {
		return nil, raw, errAuth
	}
	ts := int64(binary.BigEndian.Uint64(p1[1:9]))
	if absInt64(time.Now().Unix()-ts) > handshakeWindow {
		return nil, raw, errAuth
	}
	if allowed != nil && !allowed(cPubBytes) {
		return nil, raw, errAuth
	}
	if replay != nil && !replay.Add(ePub) {
		return nil, raw, errAuth
	}

	// -> message 2
	feph, err := GenerateKeyPair()
	if err != nil {
		return nil, raw, err
	}
	fPub := feph.PublicKey().Bytes()
	ss.mixHash(fPub)
	ee, err := dh(feph, ePubKey)
	if err != nil {
		return nil, raw, err
	}
	ss.mixKey(ee)
	se, err := dh(feph, cPubKey)
	if err != nil {
		return nil, raw, err
	}
	ss.mixKey(se)
	p2 := make([]byte, payload2PlainLen)
	p2[0] = versionV1
	copy(p2[2:], randBytes(payload2PlainLen-2))
	encP2, err := ss.encryptAndHash(p2)
	if err != nil {
		return nil, raw, err
	}
	body2 := make([]byte, 0, 80)
	body2 = append(body2, fPub...)
	body2 = append(body2, encP2...)
	salt2 := randBytes(SaltSize)
	if err := obfuscate(psk, salt2, body2); err != nil {
		return nil, raw, err
	}
	msg2 := make([]byte, 0, msg2Len)
	msg2 = append(msg2, salt2...)
	msg2 = append(msg2, body2...)
	if _, err := rw.Write(msg2); err != nil {
		return nil, raw, err
	}

	k1, k2 := ss.split()
	return &HandshakeResult{
		TxKey:      k2, // server -> client
		RxKey:      k1, // client -> server
		SessionID:  ss.h,
		PeerStatic: cPubBytes,
	}, raw, nil
}
