package network_exchange

import (
	"io"
	"sync"

	"github.com/geovex/tgp/internal/tgcrypt_encryption"
)

type obfuscatedStream struct {
	r, w     sync.Mutex
	stream   io.ReadWriteCloser
	nonce    *tgcrypt_encryption.Nonce
	protocol uint8
	obf      tgcrypt_encryption.Obfuscator
}

// create obfuscated stream if nonce is specified, initiate will send it once
func newObfuscatedStream(stream io.ReadWriteCloser, enc tgcrypt_encryption.Obfuscator, nonce *tgcrypt_encryption.Nonce, protocol uint8) *obfuscatedStream {
	return &obfuscatedStream{
		r:        sync.Mutex{},
		w:        sync.Mutex{},
		stream:   stream,
		nonce:    nonce,
		protocol: protocol,
		obf:      enc,
	}
}

func (s *obfuscatedStream) Initiate() error {
	s.w.Lock()
	defer s.w.Unlock()
	if s.nonce != nil {
		_, err := s.stream.Write(s.nonce[:])
		return err
	} else {
		return nil
	}
}

func (s *obfuscatedStream) Protocol() uint8 {
	return s.protocol
}

func (s *obfuscatedStream) Read(p []byte) (n int, err error) {
	s.r.Lock()
	defer s.r.Unlock()
	n, err = s.stream.Read(p)
	s.obf.DecryptNext(p[:n])
	return
}

func (s *obfuscatedStream) Write(p []byte) (n int, err error) {
	s.w.Lock()
	defer s.w.Unlock()
	newbuf := make([]byte, len(p))
	copy(newbuf, p)
	// TODO: may be save decrypt context here
	s.obf.EncryptNext(newbuf)
	n, err = s.stream.Write(newbuf)
	return
}

func (s *obfuscatedStream) Close() error {
	return s.stream.Close()
}
