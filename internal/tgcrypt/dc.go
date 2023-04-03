package tgcrypt

import (
	"crypto/aes"
	"crypto/cipher"
)

type DcCtx struct {
	Nonce  [InitialHeaderSize]byte
	toDc   cipher.Stream
	fromDc cipher.Stream
}

func DcCtxNew(dc int16, protocol byte) (c *DcCtx, err error) {
	header, err := genNonce()
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