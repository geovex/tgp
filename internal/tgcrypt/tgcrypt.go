// Generate init packet
package tgcrypt

import (
	"crypto/aes"
	"crypto/cipher"
)

func newAesStream(key []byte, iv []byte) cipher.Stream {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	stream := cipher.NewCTR(block, iv)
	return stream
}
