// Generate init packet
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"runtime"
)

func decryptInit(packet [initialHeaderSize]byte) (decrypt [48]byte) {
	k := 0
	for i := 55; i >= 8; i-- {
		decrypt[k] = packet[i]
		k++
	}
	return
}

// struct that handles encryption
type obfuscatedClientCtx struct {
	header     [initialHeaderSize]byte
	secret     *Secret
	protocol   uint8
	dc         int16
	random     [2]byte
	fromClient cipher.Stream
	toClient   cipher.Stream
}

func obfuscatedClientCtxFromHeader(header [initialHeaderSize]byte, secret *Secret) (c *obfuscatedClientCtx, err error) {
	encKey := header[8:40]
	encIV := header[40:56]
	decReversed := decryptInit(header)
	decKey := decReversed[:32]
	decIV := decReversed[32:48]
	secretData := secret.RawSecret[0:16]
	hasher := sha256.New()
	hasher.Write(encKey)
	hasher.Write(secretData)
	encKey = hasher.Sum(nil)
	hasher.Reset()
	hasher.Write(decKey)
	hasher.Write(secretData)
	decKey = hasher.Sum(nil)
	hasher.Reset()
	// encKey is used for receiving data bbecause abbreviations was taken from client specs
	fromClientCipher, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	fromClientStream := cipher.NewCTR(fromClientCipher, encIV)
	toClientCipher, err := aes.NewCipher(decKey)
	if err != nil {
		return nil, err
	}
	toClientStream := cipher.NewCTR(toClientCipher, decIV)
	// decrypt encrypted part of innitial packet
	// basicaly you need to appy decrypt to all incoming packet and take last 8 bytes
	buf := make([]byte, 64)
	fromClientStream.XORKeyStream(buf, header[:])
	fmt.Printf("Decrypted tail %s\n", hex.EncodeToString(buf[56:]))
	protocol := buf[56]
	dc := int16(buf[60]) + (int16(buf[61]) << 8)
	var random [2]byte
	copy(random[:], buf[62:64])
	fmt.Printf("protocol: %x. DC %x\n", protocol, dc)
	c = &obfuscatedClientCtx{
		header:     header,
		secret:     secret,
		fromClient: fromClientStream,
		toClient:   toClientStream,
		protocol:   protocol,
		dc:         dc,
		random:     random,
	}
	return
}

func (c *obfuscatedClientCtx) decryptNext(buf []byte) {
	c.fromClient.XORKeyStream(buf, buf)
}

func (c *obfuscatedClientCtx) encryptNext(buf []byte) {
	c.toClient.XORKeyStream(buf, buf)
}

var wrongNonceStarters = [...][]byte{
	{0xef},                   // abridged header
	{0x44, 0x41, 0x45, 0x48}, //HEAD
	{0x54, 0x53, 0x4f, 0x50}, //POST
	{0x20, 0x54, 0x45, 0x47}, //GET
	{0x49, 0x54, 0x50, 0x4f}, //OPTI
	{0x02, 0x01, 0x03, 0x16}, // -----?
	{0xdd, 0xdd, 0xdd, 0xdd}, // padded intermediate header
	{0xee, 0xee, 0xee, 0xee}, // intermediate header
}

type dcCtx struct {
	nonce  [initialHeaderSize]byte
	toDc   cipher.Stream
	fromDc cipher.Stream
}

func genHeader() (packet [initialHeaderSize]byte, err error) {
	// init := (56 random bytes) + protocol + dc + (2 random bytes)
	for {
		_, err = rand.Read(packet[:])
		if err != nil {
			return
		}
		runtime.Gosched()
		for _, s := range wrongNonceStarters {
			if bytes.Equal(packet[:len(s)], s) {
				continue
			}
		}
		if bytes.Equal(packet[4:8], []byte{0, 0, 0, 0}) {
			continue
		}
		return
	}
}

func dcCtxFromClient(dc int, protocol byte) (c *dcCtx, err error) {
	header, err := genHeader()
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
	var nonce [initialHeaderSize]byte
	toDcStream.XORKeyStream(nonce[:], header[:])
	copy(nonce[:56], header[:56])
	c = &dcCtx{
		nonce:  nonce,
		toDc:   toDcStream,
		fromDc: fromDcStream,
	}
	return
}

func (c *dcCtx) decryptNext(buf []byte) {
	c.fromDc.XORKeyStream(buf, buf)
}

func (c *dcCtx) encryptNext(buf []byte) {
	c.toDc.XORKeyStream(buf, buf)
}

type encDecCtx interface {
	decryptNext(buf []byte)
	encryptNext(buf []byte)
}

type encDecStream struct {
	encDec encDecCtx
	stream io.ReadWriter
}

func (ed *encDecStream) Read(buf []byte) (size int, err error) {
	size, err = ed.stream.Read(buf)
	ed.encDec.decryptNext(buf[:size])
	return
}

func (ed *encDecStream) Write(data []byte) (size int, err error) {
	//write should not transform data
	buf := make([]byte, len(data))
	copy(buf, data)
	size, err = ed.stream.Write(buf)
	ed.encDec.encryptNext(buf[:size])
	return
}
