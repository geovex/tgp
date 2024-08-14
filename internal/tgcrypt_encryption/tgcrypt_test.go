package tgcrypt_encryption

import (
	"testing"
)

func TestGenInits(t *testing.T) {
	//lint:ignore SA4006 this is a test
	init := genNonce()
	if len(init) != NonceSize {
		t.Fatal("wrong init length")
	}
}

func TestDecryptInit(t *testing.T) {
	var init [NonceSize]byte
	for i := 0; i < len(init); i++ {
		init[i] = byte(i)
	}
	dec := decryptInit(init)
	if dec[0] != 55 || dec[47] != 8 {
		t.Errorf("dec[0]=%d, dec[47]=%d", dec[0], dec[47])
	}
}
