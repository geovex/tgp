package tgcrypt_encryption

import "crypto/cipher"

// Common interface that supports encryption and decryption of obfuscated
// messages.
type Obfuscator interface {
	// decrypt supposedly received bytes in buffer and advance decryption context
	DecryptNext(buf []byte)
	// encrypt supposedly send bytes in buffer and advance encryption context
	EncryptNext(buf []byte)
}

type obfuscatorCtx struct {
	writer, reader cipher.Stream
}

func (e *obfuscatorCtx) DecryptNext(buf []byte) {
	e.reader.XORKeyStream(buf, buf)
}

func (e *obfuscatorCtx) EncryptNext(buf []byte) {
	e.writer.XORKeyStream(buf, buf)
}
