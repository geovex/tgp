package tgcrypt

import (
	"crypto/aes"
	"crypto/cipher"
)

// Context for obfuscation proxy-DC connection
type DcCtx struct {
	Nonce    Nonce
	Protocol uint8
	obf      Obfuscator
}

func DcCtxNew(dc int16, protocol byte) (c *DcCtx, err error) {
	header := genNonce()
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
	var nonce [NonceSize]byte
	toDcStream.XORKeyStream(nonce[:], header[:])
	copy(nonce[:56], header[:56])
	c = &DcCtx{
		Nonce:    nonce,
		Protocol: protocol,
		obf: &obfuscatorCtx{
			reader: fromDcStream,
			writer: toDcStream,
		},
	}
	return
}

func (c *DcCtx) DecryptNext(buf []byte) {
	c.obf.DecryptNext(buf)
}

func (c *DcCtx) EncryptNext(buf []byte) {
	c.obf.EncryptNext(buf)
}
