package tgcrypt

import "crypto/cipher"

// Common interface that supports encryption and decryption of obfuscated
// messages.
type Obfuscator interface {
	DecryptNext(buf []byte)
	EncryptNext(buf []byte)
}

type obfuscatorCtx struct {
	writer, reader cipher.Stream
}

// decrypt supposedly received bytes in buffer and advance decryption context
func (e *obfuscatorCtx) DecryptNext(buf []byte) {
	e.reader.XORKeyStream(buf, buf)
}

// encrypt supposedly send bytes in buffer and advance encryption context
func (e *obfuscatorCtx) EncryptNext(buf []byte) {
	e.writer.XORKeyStream(buf, buf)
}
