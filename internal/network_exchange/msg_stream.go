package network_exchange

import (
	"github.com/geovex/tgp/internal/network_exchange/streams"
)

type message struct {
	data     []byte // if nil, skip send
	quickack bool
	seq      uint32
}

//lint:ignore U1000 will be used later
func transceiveStreamsAsMsg(client, dc streams.DataStream) (errc, errd error) {
	defer client.Close()
	defer dc.Close()
	clientStream := newRawMsgStream(client)
	dcStream := newRawMsgStream(dc)
	return streams.TransceiveMsg(clientStream, dcStream)
}
