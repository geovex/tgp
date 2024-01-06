package tgcrypt

import (
	"bytes"
	"crypto/rand"
	"runtime"
)

const NonceSize = 64

// nonce is a set of bytes, received when initiating encrypted connection
type Nonce [NonceSize]byte

var WrongNonceStarters = [...][]byte{
	{0xef},                   // abridged header
	{0x48, 0x45, 0x41, 0x44}, //HEAD
	{0x50, 0x4f, 0x53, 0x54}, //POST
	{0x47, 0x45, 0x54, 0x20}, //GET
	{0x4f, 0x50, 0x54, 0x49}, //OPTI
	{0x16, 0x03, 0x01, 0x02}, //FakeTLS
	{0xdd, 0xdd, 0xdd, 0xdd}, // padded intermediate header
	{0xee, 0xee, 0xee, 0xee}, // intermediate header
}

func decryptInit(packet Nonce) (decrypt [48]byte) {
	k := 0
	for i := 55; i >= 8; i-- {
		decrypt[k] = packet[i]
		k++
	}
	return
}

// Check if nonce is correct. Usefull for clients validation
func IsWrongNonce(nonce Nonce) bool {
	for _, s := range WrongNonceStarters {
		if bytes.Equal(nonce[:len(s)], s) {
			return true
		}
	}
	return bytes.Equal(nonce[4:8], []byte{0, 0, 0, 0})
}

func genNonce() (packet Nonce) {
	// init := (56 random bytes) + protocol + dc + (2 random bytes)
	for {
		_, err := rand.Read(packet[:])
		if err != nil {
			panic(err)
		}
		runtime.Gosched()
		if IsWrongNonce(packet) {
			continue
		}
		return
	}
}
