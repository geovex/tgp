package obfuscated

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	mrand "math/rand"
	"runtime"
	"sync"
	"time"

	"github.com/geovex/tgp/internal/tgcrypt"
)

func (o *ClientHandler) handleFakeTls(initialPacket [tgcrypt.NonceSize]byte) (err error) {
	var tlsHandshake [tgcrypt.FakeTlsHandshakeLen]byte
	copy(tlsHandshake[:tgcrypt.FakeTlsHandshakeLen], initialPacket[:])
	_, err = io.ReadFull(o.client, tlsHandshake[tgcrypt.NonceSize:])
	var clientCtx *tgcrypt.FakeTlsCtx
	if err != nil {
		return
	}
	for u := range o.config.IterateUsers() {
		runtime.Gosched()
		userSecret, err := tgcrypt.NewSecretHex(u.Secret)
		if err != nil {
			continue
		}
		clientCtx, err = tgcrypt.FakeTlsCtxFromTlsHeader(tlsHandshake, userSecret)
		if err != nil {
			continue
		} else {
			o.user = u
			fmt.Printf("Client connected %s (faketls)\n", u.Name)
			break
		}
	}
	if o.user == nil {
		return o.handleFallBack(tlsHandshake[:])
	}
	o.statsHandle.SetAuthorized(o.user.Name)
	err = o.transceiveFakeTls(clientCtx)
	fmt.Printf("Client disconnected %s (faketls) \n", o.user.Name)
	return err
}

func (o *ClientHandler) transceiveFakeTls(cryptClient *tgcrypt.FakeTlsCtx) error {
	// checking timestamp
	// TODO: consider it optional
	skew := time.Now().UTC().Unix() - int64(cryptClient.Timestamp)
	skewAbs := skew
	if skewAbs < 0 {
		skewAbs = -skewAbs
	}
	if skewAbs > 1000 {
		return fmt.Errorf("time skew too big: %d", skewAbs)
	}
	zero32 := make([]byte, 32)
	sessionIdLen := cryptClient.Header[43]
	sessionId := cryptClient.Header[44 : 44+sessionIdLen]
	toClientHello := make([]byte, 0, 118)
	toClientHello = append(toClientHello, 0x03, 0x03) // tls version 3,3 means tls 1.2
	toClientHello = append(toClientHello, zero32...)
	toClientHello = append(toClientHello, sessionIdLen)
	toClientHello = append(toClientHello, sessionId...)
	toClientHello = append(toClientHello, 0x13, 0x01) // tls ciphersuite TLS_AES_128_GCM_SHA256
	toClientHello = append(toClientHello, 0x00)       // compression method none
	tlsExtensions := []byte{
		0x00, 0x2e, //length
		0x00, 0x33, 0x00, 0x24, // tls extension key share
		0x00, 0x1d, 0x00, 0x20, // named group for key x25519
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("can't generate fake key: %w", err)
	}
	tlsExtensions = append(tlsExtensions, publicKey...)
	tlsExtensions = append(tlsExtensions, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04) // supported versions 3 and 4
	toClientHello = append(toClientHello, tlsExtensions...)
	toClientHelloPkt := make([]byte, 0, 2000)
	toClientHelloPkt = append(toClientHelloPkt,
		0x16,       // handhake record
		0x03, 0x03, // protocol version 3,3 means tls 1.2
	)
	toClientHelloPkt = append(toClientHelloPkt, binary.BigEndian.AppendUint16(nil, uint16(len(toClientHello)+4))...)
	toClientHelloPkt = append(toClientHelloPkt, 0x02)
	toClientHelloPkt = append(toClientHelloPkt, binary.BigEndian.AppendUint32(nil, uint32(len(toClientHello)))[1:]...)
	toClientHelloPkt = append(toClientHelloPkt, toClientHello...)
	toClientHelloPkt = append(toClientHelloPkt, 0x14, 0x03, 0x03, 0x00, 0x01, 0x01) //change cipher
	toClientHelloPkt = append(toClientHelloPkt, 0x17, 0x03, 0x03)                   // tls app http2 header
	// TODO consider fetch original cert
	httpData := make([]byte, mrand.Intn(4000)+1000)
	_, err = io.ReadFull(rand.Reader, httpData)
	if err != nil {
		return fmt.Errorf("can't create fake cert data: %w", err)
	}
	toClientHelloPkt = append(toClientHelloPkt, binary.BigEndian.AppendUint16(nil, uint16(len(httpData)))...)
	toClientHelloPkt = append(toClientHelloPkt, httpData...)
	h := hmac.New(sha256.New, cryptClient.Secret.RawSecret)
	h.Write(cryptClient.Digest[:])
	h.Write(toClientHelloPkt)
	toClientDigest := h.Sum(nil)
	copy(toClientHelloPkt[11:], toClientDigest)
	_, err = o.client.Write(toClientHelloPkt)
	if err != nil {
		return err
	}
	fts := newFakeTlsStream(o.client, cryptClient)
	var simpleHeader [tgcrypt.NonceSize]byte
	_, err = io.ReadFull(fts, simpleHeader[:])
	if err != nil {
		return fmt.Errorf("can't read inner simple header: %w", err)
	}
	o.cliCtx, err = tgcrypt.ObfCtxFromNonce(simpleHeader, cryptClient.Secret)
	if err != nil {
		return fmt.Errorf("can't create simple ctx from inner simple header: %w", err)
	}
	o.cliStream = newObfuscatedStream(fts, o.cliCtx, &o.cliCtx.Nonce, o.cliCtx.Protocol)
	err = o.processWithConfig()
	fmt.Printf("Client disconnected %s (faketls)\n", o.user.Name)
	return err
}

type fakeTlsStream struct {
	readlock, writelock sync.Mutex
	client              io.ReadWriteCloser
	readerTail          []byte
}

func newFakeTlsStream(client io.ReadWriteCloser, crypt *tgcrypt.FakeTlsCtx) *fakeTlsStream {
	return &fakeTlsStream{
		readlock:   sync.Mutex{},
		writelock:  sync.Mutex{},
		client:     client,
		readerTail: []byte{},
	}
}

func (f *fakeTlsStream) readPacket() ([]byte, error) {
	var buf [5]byte
	for {
		_, err := io.ReadFull(f.client, buf[:])
		if err != nil {
			return nil, err
		}
		recType := buf[0]
		if recType != 0x14 && recType != 0x17 {
			return nil, fmt.Errorf("unexpected record type %x", recType)
		}
		if !bytes.Equal(buf[1:3], []byte{0x03, 0x03}) {
			return nil, fmt.Errorf("unexpcted tls version %x %x", buf[1], buf[2])
		}
		length := binary.BigEndian.Uint16(buf[3:5])
		data := make([]byte, length)
		_, err = io.ReadFull(f.client, data)
		if err != nil {
			return nil, err
		}
		if recType == 0x14 {
			continue
		}
		return data, nil
	}
}

func (f *fakeTlsStream) Read(b []byte) (n int, err error) {
	f.readlock.Lock()
	defer f.readlock.Unlock()
	var data []byte
	if len(f.readerTail) > 0 {
		n = copy(b, f.readerTail)
		f.readerTail = f.readerTail[n:]
		return n, nil
	} else {
		data, err = f.readPacket()
		if err != nil {
			return 0, err
		}
		f.readerTail = append(f.readerTail, data...)
		n = copy(b, f.readerTail)
		f.readerTail = f.readerTail[n:]
		return n, nil
	}
}

func (f *fakeTlsStream) Write(b []byte) (n int, err error) {
	f.writelock.Lock()
	defer f.writelock.Unlock()
	i := 0
	const chunkSize = 1 << 14 // mtproto has 16384 + 24
	for i < len(b) {
		rest := b[i:]
		var transmitlen uint16
		if len(rest) > chunkSize {
			transmitlen = chunkSize
		} else {
			transmitlen = uint16(len(rest))
		}
		buf := make([]byte, 0, transmitlen+5)
		buf = append(buf, 0x17, 0x03, 0x03)
		buf = binary.BigEndian.AppendUint16(buf, transmitlen)
		buf = append(buf, rest[:transmitlen]...)
		_, err = f.client.Write(buf)
		if err != nil {
			return i, err
		}
		i += int(transmitlen)
	}
	return len(b), nil
}

func (f *fakeTlsStream) Close() error {
	err := f.client.Close()
	if err != nil {
		return err
	}
	f.readlock.Lock()
	defer f.readlock.Unlock()
	f.writelock.Lock()
	defer f.writelock.Unlock()
	f.readerTail = []byte{}
	return nil
}
