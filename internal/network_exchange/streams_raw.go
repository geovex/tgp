package network_exchange

import (
	"fmt"
	"io"
	"sync"

	"github.com/geovex/tgp/internal/tgcrypt_encryption"
)

type rawStream struct {
	r, w     sync.Mutex
	protocol uint8
	stream   io.ReadWriteCloser
}

func newRawStream(stream io.ReadWriteCloser, protocol uint8) *rawStream {
	return &rawStream{
		r:        sync.Mutex{},
		w:        sync.Mutex{},
		stream:   stream,
		protocol: protocol,
	}
}

func (s *rawStream) Initiate() error {
	s.w.Lock()
	defer s.w.Unlock()
	var header []byte
	switch s.protocol {
	case tgcrypt_encryption.Abridged:
		header = []byte{tgcrypt_encryption.Abridged}
	case tgcrypt_encryption.Intermediate:
		header = []byte{tgcrypt_encryption.Intermediate, tgcrypt_encryption.Intermediate, tgcrypt_encryption.Intermediate, tgcrypt_encryption.Intermediate}
	case tgcrypt_encryption.Padded:
		header = []byte{tgcrypt_encryption.Padded, tgcrypt_encryption.Padded, tgcrypt_encryption.Padded, tgcrypt_encryption.Padded}
	case tgcrypt_encryption.Full: // do nothing for Full protocol
		return nil
	default:
		return fmt.Errorf("unknown protocol: %d", s.protocol)
	}
	_, err := s.stream.Write(header)
	return err
}

func (s *rawStream) Protocol() uint8 {
	return s.protocol
}

func (s *rawStream) Read(p []byte) (n int, err error) {
	s.r.Lock()
	defer s.r.Unlock()
	n, err = s.stream.Read(p)
	return
}

func (s *rawStream) Write(p []byte) (n int, err error) {
	s.w.Lock()
	defer s.w.Unlock()
	n, err = s.stream.Write(p)
	return
}

func (s *rawStream) Close() error {
	return s.stream.Close()
}
