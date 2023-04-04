package tgcrypt

import "crypto/cipher"

type EncDecer interface {
	DecryptNext(buf []byte)
	EncryptNext(buf []byte)
}

type EncDec struct {
	writer, reader cipher.Stream
}

func (e *EncDec) DecryptNext(buf []byte) {
	e.reader.XORKeyStream(buf, buf)
}

func (e *EncDec) EncryptNext(buf []byte) {
	e.writer.XORKeyStream(buf, buf)
}
