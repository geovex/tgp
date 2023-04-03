package obfuscated

import (
	"fmt"
	"io"
	"runtime"
	"sync"

	"github.com/geovex/tgp/internal/tgcrypt"
)

func (o ObfuscatedHandler) handleSimple(initialPacket [tgcrypt.InitialHeaderSize]byte) (err error) {
	var cryptClient *tgcrypt.SimpleClientCtx
	var user *string
	o.config.IterateUsers(func(u, s string) bool {
		runtime.Gosched()
		if tgcrypt.IsWrongNonce(initialPacket) {
			return false
		}
		userSecret, err := tgcrypt.NewSecretHex(s)
		if err != nil {
			return false
		}
		cryptClient, err = tgcrypt.SimpleClientCtxFromHeader(initialPacket, userSecret)
		if err != nil {
			return false
		}
		// basic afterchecks
		if cryptClient.Dc > dcMaxIdx || cryptClient.Dc < -dcMaxIdx || cryptClient.Dc == 0 {
			return false
		}
		user = &u
		fmt.Printf("Client connected %s, protocol: %x\n", u, cryptClient.Protocol)
		return true
	})
	if user == nil {
		return o.handleFallBack(initialPacket[:])
	}
	//connect to dc
	s, err := o.config.GetSocks5(*user)
	if err != nil {
		panic("user found, but GetUser not")
	}

	dcconn, err := dcConnectorFromSocks(s, o.config.GetAllowIPv6())
	if err != nil {
		return err
	}
	dcSock, err := dcconn.ConnectDC(cryptClient.Dc)
	if err != nil {
		return err
	}
	cryptDc, err := tgcrypt.DcCtxNew(cryptClient.Dc, cryptClient.Protocol)
	if err != nil {
		return err
	}
	dcStream, err := LoginDC(dcSock, cryptDc)
	if err != nil {
		return err
	}
	defer dcStream.Close()
	clientStream := NewSimpleStream(o.client, cryptClient)
	defer clientStream.Close()
	transceiveStreams(clientStream, dcStream)
	fmt.Printf("Client disconnected %s\n", *user)
	return nil
}

type SimpleStream struct {
	readlock, writelock sync.RWMutex
	client              io.ReadWriteCloser
	ctx                 *tgcrypt.SimpleClientCtx
}

func NewSimpleStream(client io.ReadWriteCloser, ctx *tgcrypt.SimpleClientCtx) *SimpleStream {
	return &SimpleStream{
		client:    client,
		ctx:       ctx,
		readlock:  sync.RWMutex{},
		writelock: sync.RWMutex{},
	}
}

func (s *SimpleStream) Read(b []byte) (n int, err error) {
	s.readlock.RLock()
	defer s.readlock.RUnlock()
	n, err = s.client.Read(b)
	s.ctx.DecryptNext(b[:n])
	return
}

func (s *SimpleStream) Write(b []byte) (n int, err error) {
	s.writelock.Lock()
	defer s.writelock.Unlock()
	// TODO may be preserve encryption state
	writebuf := make([]byte, 0, len(b))
	writebuf = append(writebuf, b...)
	s.ctx.EncryptNext(writebuf)
	n, err = s.client.Write(writebuf)
	return
}

func (s *SimpleStream) Close() error {
	return s.client.Close()
}
