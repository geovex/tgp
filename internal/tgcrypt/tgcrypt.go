// Generate init packet
package tgcrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"runtime"
)

const InitialHeaderSize = 64

var WrongNonceStarters = [...][]byte{
	{0xef},                   // abridged header
	{0x48, 0x45, 0x41, 0x44}, //HEAD
	{0x50, 0x4f, 0x53, 0x54}, //POST
	{0x47, 0x45, 0x54, 0x20}, //GET
	{0x4f, 0x50, 0x54, 0x49}, //OPTI
	{0x16, 0x03, 0x01, 0x02}, //FakeTLS
	{0xdd, 0xdd, 0xdd, 0xdd}, // padded intermediate header
	{0xee, 0xee, 0xee, 0xee}, // intermediate header
}

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

const FakeTlsHandshakeLen = 1 + 2 + 2 + 512 // handshake version payload_length length

func decryptInit(packet [InitialHeaderSize]byte) (decrypt [48]byte) {
	k := 0
	for i := 55; i >= 8; i-- {
		decrypt[k] = packet[i]
		k++
	}
	return
}

// struct that handles encryption
type SimpleClientCtx struct {
	Header     []byte
	Secret     *Secret
	Protocol   uint8
	Dc         int16
	Random     [2]byte
	fromClient cipher.Stream
	toClient   cipher.Stream
}

const (
	abridged     = 0xef
	intermediate = 0xee //0xeeeeeeee
	padded       = 0xdd //0xdddddddd
	full         = 0
)

func SimpleClientCtxFromHeader(header [InitialHeaderSize]byte, secret *Secret) (c *SimpleClientCtx, err error) {
	encKey := header[8:40]
	encIV := header[40:56]
	decReversed := decryptInit(header)
	decKey := decReversed[:32]
	decIV := decReversed[32:48]
	secretData := secret.RawSecret[0:16]
	hasher := sha256.New()
	hasher.Write(encKey)
	hasher.Write(secretData)
	encKey = hasher.Sum(nil)
	hasher.Reset()
	hasher.Write(decKey)
	hasher.Write(secretData)
	decKey = hasher.Sum(nil)
	hasher.Reset()
	// encKey is used for receiving data bbecause abbreviations was taken from client specs
	fromClientCipher, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	fromClientStream := cipher.NewCTR(fromClientCipher, encIV)
	toClientCipher, err := aes.NewCipher(decKey)
	if err != nil {
		return nil, err
	}
	toClientStream := cipher.NewCTR(toClientCipher, decIV)
	// decrypt encrypted part of innitial packet
	// basicaly you need to appy decrypt to all incoming packet and take last 8 bytes
	buf := make([]byte, 64)
	fromClientStream.XORKeyStream(buf, header[:])
	// fmt.Printf("Decrypted tail %s\n", hex.EncodeToString(buf[56:]))
	protocol := buf[56]
	switch protocol {
	case abridged, intermediate, padded:
		break
	default:
		return nil, fmt.Errorf("invalid protocol %d", protocol)
	}
	if buf[57] != protocol || buf[58] != protocol || buf[59] != protocol {
		return nil, fmt.Errorf("invalid protocol fields %d %d %d %d", buf[56], buf[57], buf[58], buf[59])
	}
	dc := int16(buf[60]) + (int16(buf[61]) << 8)
	var random [2]byte
	copy(random[:], buf[62:64])
	// fmt.Printf("protocol: %x. DC %x\n", protocol, dc)
	c = &SimpleClientCtx{
		Header:     header[:],
		Secret:     secret,
		fromClient: fromClientStream,
		toClient:   toClientStream,
		Protocol:   protocol,
		Dc:         dc,
		Random:     random,
	}
	return
}

func (c *SimpleClientCtx) DecryptNext(buf []byte) {
	c.fromClient.XORKeyStream(buf, buf)
}

func (c *SimpleClientCtx) EncryptNext(buf []byte) {
	c.toClient.XORKeyStream(buf, buf)
}

type DcCtx struct {
	Nonce  [InitialHeaderSize]byte
	toDc   cipher.Stream
	fromDc cipher.Stream
}

func IsWrongNonce(nonce [InitialHeaderSize]byte) bool {
	for _, s := range WrongNonceStarters {
		if bytes.Equal(nonce[:len(s)], s) {
			return true
		}
	}
	return bytes.Equal(nonce[4:8], []byte{0, 0, 0, 0})
}

func genHeader() (packet [InitialHeaderSize]byte, err error) {
	// init := (56 random bytes) + protocol + dc + (2 random bytes)
	for {
		_, err = rand.Read(packet[:])
		if err != nil {
			return
		}
		runtime.Gosched()
		if IsWrongNonce(packet) {
			continue
		}
		return
	}
}

func DcCtxNew(dc int16, protocol byte) (c *DcCtx, err error) {
	header, err := genHeader()
	if err != nil {
		return
	}
	header[56] = protocol
	header[57] = protocol
	header[58] = protocol
	header[59] = protocol
	encKey := header[8:40]
	encIV := header[40:56]
	decReversed := decryptInit(header)
	decKey := decReversed[:32]
	decIV := decReversed[32:48]
	toDcCipher, err := aes.NewCipher(encKey)
	if err != nil {
		return
	}
	toDcStream := cipher.NewCTR(toDcCipher, encIV)
	fromDcCipher, err := aes.NewCipher(decKey)
	if err != nil {
		return
	}
	fromDcStream := cipher.NewCTR(fromDcCipher, decIV)
	var nonce [InitialHeaderSize]byte
	toDcStream.XORKeyStream(nonce[:], header[:])
	copy(nonce[:56], header[:56])
	c = &DcCtx{
		Nonce:  nonce,
		toDc:   toDcStream,
		fromDc: fromDcStream,
	}
	return
}

func (c *DcCtx) DecryptNext(buf []byte) {
	c.fromDc.XORKeyStream(buf, buf)
}

func (c *DcCtx) EncryptNext(buf []byte) {
	c.toDc.XORKeyStream(buf, buf)
}

type FakeTlsCtx struct {
	Header    [FakeTlsHandshakeLen]byte
	Digest    [32]byte
	Timestamp uint32
	Secret    *Secret
}

func FakeTlsCtxFromTlsHeader(header [FakeTlsHandshakeLen]byte, secret *Secret) (c *FakeTlsCtx, err error) {
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
