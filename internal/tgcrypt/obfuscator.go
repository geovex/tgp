package tgcrypt

import "crypto/cipher"

type Obfuscator interface {
	DecryptNext(buf []byte)
	EncryptNext(buf []byte)
}

type ObfuscatorCtx struct {
	writer, reader cipher.Stream
}

func (e *ObfuscatorCtx) DecryptNext(buf []byte) {
	e.reader.XORKeyStream(buf, buf)
}

func (e *ObfuscatorCtx) EncryptNext(buf []byte) {
	e.writer.XORKeyStream(buf, buf)
}
