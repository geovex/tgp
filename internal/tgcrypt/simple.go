package tgcrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
)

// struct that handles encryption
type SimpleClientCtx struct {
	Header   []byte
	Secret   *Secret
	Protocol uint8
	Dc       int16
	Random   [2]byte
	encdec   EncDec
}

const (
	Abridged     = 0xef
	Intermediate = 0xee //0xeeeeeeee
	Padded       = 0xdd //0xdddddddd
	Full         = 0
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
	case Abridged, Intermediate, Padded:
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
		Header:   header[:],
		Secret:   secret,
		Protocol: protocol,
		Dc:       dc,
		Random:   random,
		encdec: EncDec{
			reader: fromClientStream,
			writer: toClientStream,
		},
	}
	return
}

func (c *SimpleClientCtx) DecryptNext(buf []byte) {
	c.encdec.DecryptNext(buf)
}

func (c *SimpleClientCtx) EncryptNext(buf []byte) {
	c.encdec.EncryptNext(buf)
}
