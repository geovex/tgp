package obfuscated

import (
	"fmt"
	"io"
	"sync"

	"github.com/geovex/tgp/internal/tgcrypt"
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
	case tgcrypt.Abridged:
		header = []byte{tgcrypt.Abridged}
	case tgcrypt.Intermediate:
		header = []byte{tgcrypt.Intermediate, tgcrypt.Intermediate, tgcrypt.Intermediate, tgcrypt.Intermediate}
	case tgcrypt.Padded:
		header = []byte{tgcrypt.Padded, tgcrypt.Padded, tgcrypt.Padded, tgcrypt.Padded}
	case 0xff:
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
