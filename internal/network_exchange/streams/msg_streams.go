package streams

import (
	"io"
	"sync"
)

type MsgStream[M any] interface {
	io.Closer
	Initiate() error
	Send(M) error
	Recv() (M, error)
}

func TransceiveMsg[M any](client, remote MsgStream[M]) (err1, err2 error) {
	defer client.Close()
	defer remote.Close()
	err2 = remote.Initiate()
	if err2 != nil {
		return
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer client.Close()
		defer remote.Close()
		for {
			msg, err1 := client.Recv()
			if err1 != nil {
				return
			}
			err2 = remote.Send(msg)
			if err2 != nil {
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		defer client.Close()
		defer remote.Close()
		for {
			msg, err1 := remote.Recv()
			if err1 != nil {
				return
			}
			err2 = client.Send(msg)
			if err2 != nil {
				return
			}
		}
	}()
	wg.Wait()
	return
}
