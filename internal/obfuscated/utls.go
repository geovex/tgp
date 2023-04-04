package obfuscated

import (
	"io"
	"sync"

	"github.com/geovex/tgp/internal/tgcrypt"
)

type encDecStream struct {
	r, w   sync.Mutex
	stream io.ReadWriteCloser
	ed     tgcrypt.EncDecer
}

func newEncDecStream(stream io.ReadWriteCloser, enc tgcrypt.EncDecer) *encDecStream {
	return &encDecStream{
		r:      sync.Mutex{},
		w:      sync.Mutex{},
		stream: stream,
		ed:     enc,
	}
}

func (s *encDecStream) Read(p []byte) (n int, err error) {
	s.r.Lock()
	defer s.r.Unlock()
	n, err = s.stream.Read(p)
	s.ed.DecryptNext(p[:n])
	return
}

func (s *encDecStream) Write(p []byte) (n int, err error) {
	s.w.Lock()
	defer s.w.Unlock()
	newbuf := make([]byte, len(p))
	copy(newbuf, p)
	// TODO: save decrypt context here
	s.ed.EncryptNext(newbuf)
	n, err = s.stream.Write(newbuf)
	return
}

func (s *encDecStream) Close() error {
	return s.stream.Close()
}

func transceiveStreams(client io.ReadWriteCloser, dc io.ReadWriteCloser) (err1, err2 error) {
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
