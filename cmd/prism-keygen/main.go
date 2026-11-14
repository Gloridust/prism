// Command prism-keygen generates Prism key material under the per-client
// credential model: one long-term server X25519 keypair, plus one credential
// ({id, psk}) per office/device. Revoke a client by deleting its credential
// from the server config.
//
//	prism-keygen                生成服务器密钥对 + 1 个客户端凭据 + 可直接粘贴的配置片段
//	prism-keygen server          仅生成服务器静态密钥对
//	prism-keygen client [name]   仅生成一个客户端凭据（id + psk）
package main

import (
	"crypto/rand"
	"fmt"
	"os"

	"github.com/gloridust/prism/pkg/prism"
)

func main() {
	mode := "all"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	switch mode {
	case "server":
		priv, pub := serverKeys()
		fmt.Printf("server_private_key = %s\nserver_public_key  = %s\n", priv, pub)
	case "client":
		name := "client"
		if len(os.Args) > 2 {
			name = os.Args[2]
		}
		id, psk := clientCred()
		fmt.Printf("# credential %q\nid  = %s\npsk = %s\n", name, id, psk)
	case "all":
		priv, pub := serverKeys()
		id, psk := clientCred()
		fmt.Printf(`# ===== Prism 起步密钥材料（妥善保管，勿提交到仓库）=====

## 服务器静态密钥对（private 仅放新加坡服务器；public 发给客户端）
server_private_key = %s
server_public_key  = %s

## 一个客户端凭据（每办公室/设备一条；吊销=从服务器删除该条）
id  = %s
psk = %s

## server.json 片段：
  "private_key": "%s",
  "credentials": [ { "name": "office-1", "id": "%s", "psk": "%s" } ]

## client.json 片段：
  "server_public_key": "%s",
  "id": "%s",
  "psk": "%s"
`,
			priv, pub, id, psk,
			priv, id, psk,
			pub, id, psk)
	default:
		fmt.Fprintf(os.Stderr, "unknown mode %q (use: all | server | client [name])\n", mode)
		os.Exit(2)
	}
}

func serverKeys() (priv, pub string) {
	kp, err := prism.GenerateServerKeypair()
	if err != nil {
		fail(err)
	}
	return prism.EncodeKey(kp.Private.Bytes()), prism.EncodeKey(kp.Public.Bytes())
}

func clientCred() (id, psk string) {
	raw := make([]byte, 4)
	if _, err := rand.Read(raw); err != nil {
		fail(err)
	}
	p, err := prism.NewPSK()
	if err != nil {
		fail(err)
	}
	return prism.EncodeKey(raw), prism.EncodeKey(p)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "prism-keygen:", err)
	os.Exit(1)
}
