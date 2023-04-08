package obfuscated

import (
	"sync"
)

type message struct {
	data     []byte
	quickack bool
	seq      uint32
}

type msgStream struct {
	sock dataStream
}

func newMsgStream(sock dataStream) *msgStream {
	return &msgStream{
		sock: sock,
	}
}

func (s *msgStream) CloseStream() error {
	return s.sock.Close()
}

//lint:ignore U1000 will be used later
func transceiveMsgStreams(client, dc dataStream) error {
	defer client.Close()
	defer dc.Close()
	err := dc.Initiate()
	if err != nil {
		return err
	}
	clientStream := newMsgStream(client)
	dcStream := newMsgStream(dc)
	transceiveMsg(clientStream, dcStream)
	return nil
}

func transceiveMsg(client *msgStream, dc *msgStream) (err1, err2 error) {
	defer client.CloseStream()
	defer dc.CloseStream()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer client.CloseStream()
		defer dc.CloseStream()
		defer wg.Done()
		for {
			var msg *message
			msg, err1 = client.ReadCliMsg()
			if err1 != nil {
				return
			}
			err1 = dc.WriteSrvMsg(msg)
			if err1 != nil {
				return
			}
		}
	}()
	go func() {
		defer client.CloseStream()
		defer dc.CloseStream()
		defer wg.Done()
		for {
			var msg *message
			msg, err2 = dc.ReadSrvMsg()
			if err2 != nil {
				return
			}
			err2 = client.WriteCliMsg(msg)
			if err2 != nil {
				return
			}
		}
	}()
	wg.Wait()
	return
}
