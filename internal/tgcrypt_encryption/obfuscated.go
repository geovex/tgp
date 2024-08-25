package tgcrypt_encryption

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// Context for client-This obfuscation
type ObfCtx struct {
	// Nonce received from client
	Nonce Nonce
	// Secret from config
	Secret   *Secret
	Protocol uint8
	Dc       int16
	Random   [2]byte
	// Obfuscastor context for client-this connection
	obf Obfuscator
}

var _ Obfuscator = &ObfCtx{}

const (
	Abridged     = 0xef
	Intermediate = 0xee //0xeeeeeeee
	Padded       = 0xdd //0xdddddddd
	Full         = 0
)

type ErrInvalidProtocol struct {
	value byte
}

var _ error = &ErrInvalidProtocol{}

func (ip ErrInvalidProtocol) Error() string {
	return fmt.Sprintf("invalid protocol %x", ip.value)
}

type ErrInvalidProtocolFields struct {
	values [4]byte
}

var _ error = &ErrInvalidProtocolFields{}

func (ipf ErrInvalidProtocolFields) Error() string {
	return fmt.Sprintf("invalid protocol fields %x %x %x %x", ipf.values[0], ipf.values[1], ipf.values[2], ipf.values[3])
}

// Generate client-this encryption context
func ObfCtxFromNonce(header Nonce, secret *Secret) (c *ObfCtx, err error) {
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
	fromClientStream := newAesStream(encKey, encIV)
	toClientStream := newAesStream(decKey, decIV)
	// decrypt encrypted part of innitial packet
	// basicaly you need to appy decrypt to all incoming packet and take last 8 bytes
	buf := make([]byte, 64)
	fromClientStream.XORKeyStream(buf, header[:])
	// fmt.Printf("Decrypted tail %s\n", hex.EncodeToString(buf[56:]))
	protocol := buf[56]
	switch protocol {
	case Abridged, Intermediate, Padded:
		break
	default:
		return nil, &ErrInvalidProtocol{value: protocol}
	}
	if buf[57] != protocol || buf[58] != protocol || buf[59] != protocol {
		return nil, &ErrInvalidProtocolFields{values: [4]byte{buf[56], buf[57], buf[58], buf[59]}}
	}
	dc := int16(binary.LittleEndian.Uint16(buf[60:62]))
	var random [2]byte
	copy(random[:], buf[62:64])
	// fmt.Printf("protocol: %x. DC %x\n", protocol, dc)
	c = &ObfCtx{
		Nonce:    header,
		Secret:   secret,
		Protocol: protocol,
		Dc:       dc,
		Random:   random,
		obf: &obfuscatorCtx{
			reader: fromClientStream,
			writer: toClientStream,
		},
	}
	return
}

func (c *ObfCtx) DecryptNext(buf []byte) {
	c.obf.DecryptNext(buf)
}

func (c *ObfCtx) EncryptNext(buf []byte) {
	c.obf.EncryptNext(buf)
}
