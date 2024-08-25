package tgcrypt_encryption

import (
	"encoding/hex"
	"fmt"
)

type SecretType int

const simpleSecretLen = 16

const (
	Simple  SecretType = 1
	Secured SecretType = 2
	FakeTLS SecretType = 3
)

type Secret struct {
	RawSecret []byte
	Type      SecretType
	Tag       byte
	Fakehost  string
}

// Generate secret from  hex string
func NewSecretHex(secret string) (*Secret, error) {
	secretBytes, err := hex.DecodeString(secret)
	if err != nil {
		return nil, err
	}
	return NewSecret(secretBytes)
}

type ErrSecretLength struct {
	length int
}

var _ error = &ErrSecretLength{}

func (e ErrSecretLength) Error() string {
	return fmt.Sprintf("incorrect secret length: %d", e.length)
}

// Generate secret from byte array
func NewSecret(secret []byte) (*Secret, error) {
	switch {
	case len(secret) == simpleSecretLen:
		return &Secret{
			RawSecret: secret,
			Type:      Simple,
		}, nil
	case len(secret) == simpleSecretLen+1:
		return &Secret{
			RawSecret: secret[1 : simpleSecretLen+1],
			Type:      Secured,
			Tag:       secret[0],
		}, nil
	case len(secret) > simpleSecretLen+1:
		return &Secret{
			RawSecret: secret[1 : simpleSecretLen+1],
			Type:      FakeTLS,
			Tag:       secret[0],
			Fakehost:  string(secret[simpleSecretLen+1:]),
		}, nil
	default:
		return nil, &ErrSecretLength{length: len(secret)}
	}
}
