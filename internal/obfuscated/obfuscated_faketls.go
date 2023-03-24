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
	"net"
	"runtime"
	"time"

	"github.com/geovex/tgp/internal/config"
	"github.com/geovex/tgp/internal/tgcrypt"
)

func handleFakeTls(initialPacket [tgcrypt.InitialHeaderSize]byte, stream net.Conn, dcConn DCConnector, users *config.Users) (err error) {
	var tlsHandshake [tgcrypt.FakeTlsHandshakeLen]byte
	copy(tlsHandshake[:tgcrypt.FakeTlsHandshakeLen], initialPacket[:])
	_, err = io.ReadFull(stream, tlsHandshake[tgcrypt.InitialHeaderSize:])
	var clientCtx *tgcrypt.FakeTlsCtx
	if err != nil {
		return
	}
	fmt.Println("faketls detected")
	var user string
	for u, s := range users.Users {
		runtime.Gosched()
		secret, err := tgcrypt.NewSecretHex(s)
		if err != nil {
			continue
		}
		clientCtx, err = tgcrypt.FakeTlsCtxFromTlsHeader(tlsHandshake, secret)
		if err != nil {
			continue
		} else {
			user = u
			fmt.Printf("Client connected %s by faketls\n", user)
			break
		}
	}
	if clientCtx == nil {
		return fmt.Errorf("user not found by secret")
	}
	transceiveFakeTls(stream, clientCtx, dcConn)
	return nil
}

func transceiveFakeTls(client net.Conn, cryptClient *tgcrypt.FakeTlsCtx, dcConn DCConnector) error {
	defer client.Close()
	// checking timestamp
	// TODO: consider it optional
	skew := time.Now().Unix() - int64(cryptClient.Timestamp)
	if skew < 0 {
		skew = -skew
	}
	if skew > 1000 {
		return fmt.Errorf("time skew too big")
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
		return err
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
		return err
	}
	toClientHelloPkt = append(toClientHelloPkt, binary.BigEndian.AppendUint16(nil, uint16(len(httpData)))...)
	toClientHelloPkt = append(toClientHelloPkt, httpData...)
	h := hmac.New(sha256.New, cryptClient.Secret.RawSecret)
	h.Write(cryptClient.Digest[:])
	h.Write(toClientHelloPkt)
	toClientDigest := h.Sum(nil)
	copy(toClientHelloPkt[11:], toClientDigest)
	_, err = client.Write(toClientHelloPkt)
	if err != nil {
		return err
	}
	fts := newFakeTlsStream(cryptClient)
	var simpleHeader [tgcrypt.InitialHeaderSize]byte
	err = fts.ReadFull(client, simpleHeader[:])
	if err != nil {
		return err
	}
	simpleCtx, err := tgcrypt.SimpleClientCtxFromHeader(simpleHeader, cryptClient.Secret)
	if err != nil {
		return err
	}
	dc, err := dcConn.ConnectDC(simpleCtx.Dc)
	if err != nil {
		return err
	}
	cryptDc, err := tgcrypt.DcCtxNew(simpleCtx.Dc, simpleCtx.Protocol)
	if err != nil {
		return err
	}
	readerJoinChannel := make(chan error, 1)
	go func() {
		defer client.Close()
		defer dc.Close()
		_, err := dc.Write(cryptDc.Nonce[:])
		if err != nil {
			readerJoinChannel <- err
			return
		}
		buf := make([]byte, 2048)
		for {
			n, err := fts.Read(client, buf)
			if err != nil || n == 0 {
				readerJoinChannel <- err
				return
			}
			simpleCtx.DecryptNext(buf[:n])
			cryptDc.EncryptNext(buf[:n])
			_, err = dc.Write(buf[:n])
			if err != nil {
				readerJoinChannel <- err
				return
			}
		}
	}()
	writerJoinChannel := make(chan error, 1)
	go func() {
		defer client.Close()
		defer dc.Close()
		buf := make([]byte, 2048)
		for {
			n, err := dc.Read(buf)
			if err != nil || n == 0 {
				writerJoinChannel <- err
				return
			}
			cryptDc.DecryptNext(buf[:n])
			simpleCtx.EncryptNext(buf[:n])
			_, err = fts.Write(client, buf[:n])
			if err != nil {
				readerJoinChannel <- err
				return
			}
		}
	}()
	<-readerJoinChannel
	<-writerJoinChannel
	return nil
}

type fakeTlsStream struct {
	cryptCtx   *tgcrypt.FakeTlsCtx
	readerTail []byte
}

func newFakeTlsStream(crypt *tgcrypt.FakeTlsCtx) *fakeTlsStream {
	return &fakeTlsStream{
		cryptCtx:   crypt,
		readerTail: []byte{},
	}
}

func (s *fakeTlsStream) readPacket(stream net.Conn) ([]byte, error) {
	for {
		var recType [1]byte
		_, err := io.ReadFull(stream, recType[:])
		if err != nil {
			return nil, err
		}
		if recType[0] != 0x14 && recType[0] != 0x17 {
			return nil, fmt.Errorf("unexpected tls record type %v", recType)
		}
		var version [2]byte
		_, err = io.ReadFull(stream, version[:])
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(version[:], []byte{0x03, 0x03}) {
			return nil, fmt.Errorf("unexpected tls version %v", version)
		}
		var lengthBuf [2]byte
		_, err = io.ReadFull(stream, lengthBuf[:])
		if err != nil {
			return nil, err
		}
		length := binary.BigEndian.Uint16(lengthBuf[:])
		// TODO check for sane length
		data := make([]byte, length)
		_, err = io.ReadFull(stream, data)
		if err != nil {
			return nil, err
		}
		if recType[0] == 0x14 {
			continue
		}
		return data, nil
	}
}

func (s *fakeTlsStream) ReadFull(stream net.Conn, b []byte) (err error) {
	for len(s.readerTail) < len(b) {
		data, err := s.readPacket(stream)
		if err != nil {
			return err
		}
		s.readerTail = append(s.readerTail, data...)
	}
	copy(b, s.readerTail)
	s.readerTail = s.readerTail[len(b):]
	return nil
}

func (s *fakeTlsStream) Read(stream net.Conn, b []byte) (n int, err error) {
	var data []byte
	if len(s.readerTail) > 0 {
		n = copy(b, s.readerTail)
		s.readerTail = s.readerTail[n:]
		return n, nil
	} else {
		data, err = s.readPacket(stream)
		if err != nil {
			return 0, err
		}
		s.readerTail = append(s.readerTail, data...)
		n = copy(b, s.readerTail)
		s.readerTail = s.readerTail[n:]
		return n, nil
	}
}

func (s *fakeTlsStream) Write(stream net.Conn, b []byte) (n int, err error) {
	i := 0
	const chunkSize = 16384 + 24
	for i < len(b) {
		rest := b[i:]
		var transmitlen uint16
		if len(rest) > chunkSize {
			transmitlen = chunkSize
		} else {
			transmitlen = uint16(len(rest))
		}
		_, err = stream.Write([]byte{0x17, 0x03, 0x03})
		if err != nil {
			return i, err
		}
		_, err = stream.Write(binary.BigEndian.AppendUint16(nil, transmitlen))
		if err != nil {
			return i, err
		}
		_, err = stream.Write(rest[:transmitlen])
		if err != nil {
			return i, err
		}
		i += int(transmitlen)
	}
	return len(b), nil
}
