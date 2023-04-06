package obfuscated

import (
	"fmt"
	"io"
	"sync"

	"github.com/geovex/tgp/internal/tgcrypt"
)

type DataStream interface {
	io.ReadWriteCloser
	Initiate() error
}

type obfuscatedStream struct {
	r, w   sync.Mutex
	stream io.ReadWriteCloser
	Nonce  *tgcrypt.Nonce
	obf    tgcrypt.Obfuscator
}

// create obfuscated stream if nonce is specified, initiate will send it once
func newObfuscatedStream(stream io.ReadWriteCloser, enc tgcrypt.Obfuscator, nonce *tgcrypt.Nonce) *obfuscatedStream {
	return &obfuscatedStream{
		r:      sync.Mutex{},
		w:      sync.Mutex{},
		stream: stream,
		Nonce:  nonce,
		obf:    enc,
	}
}

func (s *obfuscatedStream) Initiate() error {
	s.w.Lock()
	defer s.w.Unlock()
	if s.Nonce != nil {
		_, err := s.stream.Write(s.Nonce[:])
		s.Nonce = nil
		return err
	} else {
		return nil
	}
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
	// TODO: save decrypt context here
	s.obf.EncryptNext(newbuf)
	n, err = s.stream.Write(newbuf)
	return
}

func (s *obfuscatedStream) Close() error {
	return s.stream.Close()
}

func transceiveDataStreams(client, dc DataStream) (errc, errd error) {
	errd = dc.Initiate()
	if errd != nil {
		return
	}
	return transceiveStreams(client, dc)
}

func transceiveStreams(client, dc io.ReadWriteCloser) (err1, err2 error) {
	readerJoinChannel := make(chan error, 1)
	go func() {
		defer client.Close()
		defer dc.Close()
		buf := make([]byte, 2048)
		for {
			size, err := client.Read(buf)
			if err != nil {
				readerJoinChannel <- err
				return
			}
			_, err = dc.Write(buf[:size])
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
			size, err := dc.Read(buf)
			if err != nil {
				writerJoinChannel <- err
				return
			}
			_, err = client.Write(buf[:size])
			if err != nil {
				writerJoinChannel <- err
				return
			}
		}
	}()
	err1 = <-readerJoinChannel
	err2 = <-writerJoinChannel
	return
}

type rawStream struct {
	r, w     sync.Mutex
	protocol uint8 // 0xff if already initiated
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
	s.protocol = 0xff
	return err
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
