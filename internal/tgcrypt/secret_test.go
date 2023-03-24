package tgcrypt

import (
	"encoding/hex"
	"testing"
)

func TestSecretSimple(t *testing.T) {
	//lint:ignore SA4006 this is a test
	secretBytes, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	secret, err := NewSecret(secretBytes)
	if err != nil {
		t.Fatal(err)
	}
	if secret.Type != Simple {
		t.Errorf("Wrong secret type expected %d found %d", Simple, secret.Type)
	}
}

func TestSecretSecured(t *testing.T) {
	//lint:ignore SA4006 this is a test
	secretBytes, err := hex.DecodeString("dd000102030405060708090a0b0c0d0e0f")
	secret, err := NewSecret(secretBytes)
	if err != nil {
		t.Fatal(err)
	}
	if secret.Type != Secured {
		t.Errorf("Wrong secret type expected %d found %d", Secured, secret.Type)
	}
}

func TestSecretFakeTls(t *testing.T) {
	//lint:ignore SA4006 this is a test
	secretBytes, err := hex.DecodeString("ee000102030405060708090a0b0c0d0e0f676f6f676c652e636f6d")
	secret, err := NewSecret(secretBytes)
	if err != nil {
		t.Fatal(err)
	}
	if secret.Type != FakeTLS {
		t.Errorf("Wrong secret type expected %d found %d", FakeTLS, secret.Type)
	}
	if secret.Fakehost != "google.com" {
		t.Errorf("Wrong fakehost expected %s found %s", "google.com", secret.Fakehost)
	}
}

func TeestSecretError(t *testing.T) {
	//lint:ignore SA4006 this is a test
	secretBytes, err := hex.DecodeString("dd")
	_, err = NewSecret(secretBytes)
	if err == nil {
		t.Errorf("Wrong secret length passed %d", len(secretBytes))
	}
}
