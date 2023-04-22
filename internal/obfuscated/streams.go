package obfuscated

import (
	"io"
	"sync"
)

type dataStream interface {
	io.ReadWriteCloser
	Initiate() error
	Protocol() uint8
}

func transceiveDataStreams(client, dc dataStream) (errc, errd error) {
	errd = dc.Initiate()
	if errd != nil {
		return
	}
	return transceiveStreams(client, dc)
}

func transceiveStreams(client, dc io.ReadWriteCloser) (err1, err2 error) {
	defer client.Close()
	defer dc.Close()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer client.Close()
		defer dc.Close()
		defer wg.Done()
		buf := make([]byte, 2048)
		for {
			var size int
			size, err1 = client.Read(buf)
			if err1 != nil {
				return
			}
			_, err1 = dc.Write(buf[:size])
			if err1 != nil {
				return
			}
		}
	}()
	go func() {
		defer client.Close()
		defer dc.Close()
		defer wg.Done()
		buf := make([]byte, 2048)
		for {
			var size int
			size, err2 = dc.Read(buf)
			if err2 != nil {
				return
			}
			_, err2 = client.Write(buf[:size])
			if err2 != nil {
				return
			}
		}
	}()
	wg.Wait()
	return
}
