package tgcrypt

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

var FakeTlsHeader = [...]byte{
	0x16, // handhake record
	0x03, // protocol version 3.1
	0x01,
	0x02, //payload length 512
	0x00,
	0x01, // handshake message type 1 (client hello)
	0x00, // 0x1fc data follows
	0x01,
	0xfc,
	0x03, // client version 3,3 means tls 1.2
	0x03}

const FakeTlsHandshakeLen = 1 + 2 + 2 + 512 // handshake version payload_length payload

// FakeTlsHandshake is a set of bytes client supposed to send for initiate
// faketls connection.
type FakeTlsHandshake = [FakeTlsHandshakeLen]byte

type FakeTlsCtx struct {
	Header    FakeTlsHandshake
	Digest    [32]byte
	Timestamp uint32
	Secret    *Secret
}

// Checks handshake bytes against user secret (does not check timestamp)
// Returb faketls context in case os success.
func FakeTlsCtxFromTlsHeader(header FakeTlsHandshake, secret *Secret) (c *FakeTlsCtx, err error) {
	digest := header[11 : 11+32]
	msg := make([]byte, FakeTlsHandshakeLen)
	copy(msg, header[:])
	for i := 11; i < 11+32; i++ {
		msg[i] = 0
	}
	h := hmac.New(sha256.New, secret.RawSecret)
	h.Write(msg)
	digestCheck := h.Sum(nil)
	// compare ignoring timestamp
	if !bytes.Equal(digestCheck[:32-4], digest[:32-4]) {
		return nil, fmt.Errorf("invalid client digest")
	}
	var timestampBuf [4]byte
	for i := 32 - 4; i < 32; i++ {
		timestampBuf[i-(32-4)] = digest[i] ^ digestCheck[i]
	}
	timestamp := binary.LittleEndian.Uint32(timestampBuf[:])
	var digestArr [32]byte
	copy(digestArr[:], digest)
	c = &FakeTlsCtx{
		Header:    header,
		Digest:    digestArr,
		Timestamp: timestamp,
		Secret:    secret,
	}
	return c, nil
}
