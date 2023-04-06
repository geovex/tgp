package obfuscated

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/geovex/tgp/internal/tgcrypt"
)

type msg struct {
	data     []byte
	quickack bool
}

type MsgStream struct {
	sock DataStream
}

func NewMsgStream(sock DataStream) *MsgStream {
	return &MsgStream{
		sock: sock,
	}
}

func (s *MsgStream) ReadSrvMsg() (m *msg, err error) {
	var msgLen uint32
	switch s.sock.Protocol() {
	case tgcrypt.Abridged:
		var l [4]byte
		// read length
		_, err = io.ReadFull(s.sock, l[:1])
		if err != nil {
			return
		}
		if l[0]&0x80 != 0 {
			m = &msg{[]byte{l[0], 0x00, 0x00, 0x00}, true}
			fmt.Printf("server read quickack\n")
			_, err = io.ReadFull(s.sock, m.data[1:])
			m.data = []byte{m.data[3], m.data[2], m.data[1], m.data[0]}
			return
		}
		if l[0] < 0x7f {
			msgLen = uint32(l[0])
		} else {
			_, err = io.ReadFull(s.sock, l[:3])
			if err != nil {
				return
			}
			msgLen = binary.LittleEndian.Uint32(l[:])
		}
		msgLen = msgLen * 4
		// read message
		if msgLen > tgcrypt.MaxPayloadSize {
			err = fmt.Errorf("message too big: %d", msgLen)
			return
		}
	case tgcrypt.Intermediate, tgcrypt.Padded:
		// read length
		var l [4]byte
		_, err = io.ReadFull(s.sock, l[:])
		if err != nil {
			return
		}
		msgLen = binary.LittleEndian.Uint32(l[:])
		if msgLen&0x80000000 != 0 {
			fmt.Printf("server read quickack\n")
			m = &msg{l[:], true}
			return
		}
		// read message
		if msgLen > tgcrypt.MaxPayloadSize {
			err = fmt.Errorf("message too big: %d", msgLen)
			return
		}
	default:
		return nil, fmt.Errorf("unsupported protocol: %x", s.sock.Protocol())
	}
	m = &msg{data: make([]byte, msgLen), quickack: false}
	err = s.readRest(m.data)
	return
}

func (s *MsgStream) ReadCliMsg() (m *msg, err error) {
	quickack := false
	var msgbuf []byte
	var msgLen uint32
	switch s.sock.Protocol() {
	case tgcrypt.Abridged:
		var l [4]byte
		// read length
		_, err = io.ReadFull(s.sock, l[:1])
		if err != nil {
			return
		}
		if l[0]&0x80 != 0 {
			quickack = false
			l[0] &= 0x7f
		}
		if l[0] < 0x7f {
			msgLen = uint32(l[0])
		} else {
			_, err = io.ReadFull(s.sock, l[:3])
			if err != nil {
				return
			}
			msgLen = binary.LittleEndian.Uint32(l[:])
		}
		msgLen = msgLen * 4
		// read message
		msgbuf = make([]byte, msgLen)
		if msgLen > tgcrypt.MaxPayloadSize {
			err = fmt.Errorf("message too big: %d", msgLen)
			return
		}
		_, err = io.ReadFull(s.sock, msgbuf)
		if err != nil {
			return
		}
	case tgcrypt.Intermediate, tgcrypt.Padded:
		// read length
		var l [4]byte
		_, err = io.ReadFull(s.sock, l[:])
		if err != nil {
			return
		}
		msgLen = binary.LittleEndian.Uint32(l[:])
		if msgLen&0x80000000 != 0 {
			quickack = true
			msgLen &= 0x7fffffff
		}
		// read message
		if msgLen > tgcrypt.MaxPayloadSize {
			err = fmt.Errorf("message too big: %d", msgLen)
			return
		}
		msgbuf = make([]byte, msgLen)
		_, err = io.ReadFull(s.sock, msgbuf)
		if err != nil {
			return
		}
	default:
		return nil, fmt.Errorf("unsupported protocol: %x", s.sock.Protocol())
	}
	m = &msg{data: msgbuf, quickack: quickack}
	return
}

func (s *MsgStream) readRest(buf []byte) error {
	_, err := io.ReadFull(s.sock, buf)
	return err
}

func (s *MsgStream) WriteSrvMsg(m *msg) (err error) {
	sendmsg := make([]byte, 0, len(m.data)+20)
	switch s.sock.Protocol() {
	case tgcrypt.Abridged:
		l := uint32(len(m.data))
		if l%4 != 0 {
			return fmt.Errorf("message size not multiple of 4")
		}
		l = l / 4
		if l >= 0x7f {
			sendmsg = append(sendmsg, 0x7f)
			sendmsg = append(sendmsg, binary.LittleEndian.AppendUint32(nil, l)[:3]...)
		} else {
			sendmsg = append(sendmsg, byte(l))
		}
		sendmsg = append(sendmsg, m.data...)
		if m.quickack {
			sendmsg[0] |= 0x80
			sendmsg = []byte{sendmsg[3], sendmsg[2], sendmsg[1], sendmsg[0]}
		}
	case tgcrypt.Intermediate, tgcrypt.Padded:
		sendmsg = binary.LittleEndian.AppendUint32(sendmsg, uint32(len(m.data)))
		sendmsg = append(sendmsg, m.data...)
		if m.quickack {
			sendmsg[3] |= 0x80
		}
	default:
		fmt.Printf("Srv unsupported protocol: %x\n", s.sock.Protocol())
		return fmt.Errorf("unsupported protocol: %x", s.sock.Protocol())
	}
	_, err = s.sock.Write(sendmsg)
	return
}
func (s *MsgStream) WriteCliMsg(m *msg) (err error) {
	if m.quickack {
		fmt.Printf("clieent write quickack %d bytes\n", len(m.data))
		_, err = s.sock.Write(m.data)
		return
	}
	sendmsg := make([]byte, 0, len(m.data)+20)
	switch s.sock.Protocol() {
	case tgcrypt.Abridged:
		l := uint32(len(m.data))
		if l%4 != 0 {
			return fmt.Errorf("message size not multiple of 4")
		}
		l = l / 4
		if l >= 0x7f {
			sendmsg = append(sendmsg, 0x7f)
			sendmsg = append(sendmsg, binary.LittleEndian.AppendUint32(nil, l)[:3]...)
		} else {
			sendmsg = append(sendmsg, byte(l))
		}
		sendmsg = append(sendmsg, m.data...)
	case tgcrypt.Intermediate, tgcrypt.Padded:
		sendmsg = binary.LittleEndian.AppendUint32(sendmsg, uint32(len(m.data)))
		sendmsg = append(sendmsg, m.data...)
	default:
		fmt.Printf("Cli unsupported protocol: %x\n", s.sock.Protocol())
		return fmt.Errorf("unsupported protocol: %x", s.sock.Protocol())
	}
	_, err = s.sock.Write(sendmsg)
	return
}

func (s *MsgStream) CloseStream() error {
	return s.sock.Close()
}

func transceiveMsg(client *MsgStream, dc *MsgStream) {
	defer client.CloseStream()
	defer dc.CloseStream()
	readerJoinChannel := make(chan error, 1)
	go func() {
		defer client.CloseStream()
		defer dc.CloseStream()
		for {
			msg, err := client.ReadCliMsg()
			if err != nil {
				readerJoinChannel <- err
				return
			}
			err = dc.WriteSrvMsg(msg)
			if err != nil {
				readerJoinChannel <- err
				return
			}
		}
	}()
	writerJoinChannel := make(chan error, 1)
	go func() {
		defer client.CloseStream()
		defer dc.CloseStream()
		for {
			msg, err := dc.ReadSrvMsg()
			if err != nil {
				writerJoinChannel <- err
				return
			}
			err = client.WriteCliMsg(msg)
			if err != nil {
				writerJoinChannel <- err
				return
			}
		}
	}()
	<-readerJoinChannel
	<-writerJoinChannel
}

//lint:ignore U1000 will be used later
func transceiveMsgStreams(client, dc DataStream) error {
	defer client.Close()
	defer dc.Close()
	err := dc.Initiate()
	if err != nil {
		return err
	}
	clientStream := NewMsgStream(client)
	dcStream := NewMsgStream(dc)
	transceiveMsg(clientStream, dcStream)
	return nil
}
