package network_exchange

import (
	"io"
	"sync"

	"github.com/geovex/tgp/internal/network_exchange/streams"
)

type message struct {
	data     []byte // if nil, skip send
	quickack bool
	seq      uint32
}

// type msgStreamSrv interface {
// 	io.Closer
// 	Initiate() error
// 	Recv() (*message, error)
// 	Send(m *message) error
// }

type msgStreamCli interface {
	io.Closer
	ReadCliMsg() (*message, error)
	WriteCliMsg(m *message) error
}

type msgStream struct {
	sock streams.DataStream
}

// var _ streams.DataStream = MsgStream{}

func newMsgStream(sock streams.DataStream) *msgStream {
	return &msgStream{
		sock: sock,
	}
}

func (s *msgStream) Close() error {
	return s.sock.Close()
}

// initiate msg stream by sending apropriate message
func (s *msgStream) Initiate() error {
	return s.sock.Initiate()
}

//lint:ignore U1000 will be used later
func transceiveMsgStreams(client, dc streams.DataStream) (errc, errd error) {
	defer client.Close()
	defer dc.Close()
	clientStream := newMsgStream(client)
	dcStream := newDcMsgStream(dc)
	return transceiveMsg(clientStream, dcStream)
}

func transceiveMsg(client msgStreamCli, dc streams.MsgStream[*message]) (err1, err2 error) {
	defer client.Close()
	defer dc.Close()
	err2 = dc.Initiate()
	if err2 != nil {
		return
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer client.Close()
		defer dc.Close()
		defer wg.Done()
		for {
			var msg *message
			msg, err1 = client.ReadCliMsg()
			if err1 != nil {
				return
			}
			if msg.data != nil {
				//fmt.Printf("client msg: %d bytes \n", len(msg.data))
				err1 = dc.Send(msg)
				if err1 != nil {
					return
				}
			}
		}
	}()
	go func() {
		defer dc.Close()
		defer client.Close()
		defer wg.Done()
		for {
			var msg *message
			msg, err2 = dc.Recv()
			if err2 != nil {
				return
			}
			if msg.data != nil {
				//fmt.Printf("srv msg: %d bytes \n", len(msg.data))
				err2 = client.WriteCliMsg(msg)
				if err2 != nil {
					return
				}
			}
		}
	}()
	wg.Wait()
	return
}
