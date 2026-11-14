package prism

import "encoding/base64"

// 密钥文本编码：Base64URL 无填充（见 docs/PROTOCOL.md §2）。
var keyEnc = base64.URLEncoding.WithPadding(base64.NoPadding)

// EncodeKey 把原始字节编码为可写入配置的文本。
func EncodeKey(b []byte) string { return keyEnc.EncodeToString(b) }

// DecodeKey 解析配置中的密钥文本。
func DecodeKey(s string) ([]byte, error) { return keyEnc.DecodeString(s) }
