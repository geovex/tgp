package obfuscated

import (
	"encoding/binary"
	"fmt"
	"io"
	"sync"

	"github.com/geovex/tgp/internal/tgcrypt"
)

type message struct {
	data     []byte
	quickack bool
}

type msgStream struct {
	sock dataStream
}

func newMsgStream(sock dataStream) *msgStream {
	return &msgStream{
		sock: sock,
	}
}

func (s *msgStream) ReadSrvMsg() (m *message, err error) {
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
			m = &message{[]byte{l[0], 0x00, 0x00, 0x00}, true}
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
			m = &message{l[:], true}
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
	m = &message{data: make([]byte, msgLen), quickack: false}
	err = s.readRest(m.data)
	return
}

func (s *msgStream) ReadCliMsg() (m *message, err error) {
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
	m = &message{data: msgbuf, quickack: quickack}
	return
}

func (s *msgStream) readRest(buf []byte) error {
	_, err := io.ReadFull(s.sock, buf)
	return err
}

func (s *msgStream) WriteSrvMsg(m *message) (err error) {
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
			fmt.Printf("server write quickack\n")
			sendmsg[0] |= 0x80
			sendmsg = []byte{sendmsg[3], sendmsg[2], sendmsg[1], sendmsg[0]}
		}
	case tgcrypt.Intermediate, tgcrypt.Padded:
		sendmsg = binary.LittleEndian.AppendUint32(sendmsg, uint32(len(m.data)))
		sendmsg = append(sendmsg, m.data...)
		if m.quickack {
			fmt.Printf("server write quickack\n")
			sendmsg[3] |= 0x80
		}
	default:
		fmt.Printf("Srv unsupported protocol: %x\n", s.sock.Protocol())
		return fmt.Errorf("unsupported protocol: %x", s.sock.Protocol())
	}
	_, err = s.sock.Write(sendmsg)
	return
}
func (s *msgStream) WriteCliMsg(m *message) (err error) {
	sendmsg := make([]byte, 0, len(m.data)+20)
	if m.quickack {
		fmt.Printf("clieent write quickack %d bytes\n", len(m.data))
		if s.sock.Protocol() == tgcrypt.Abridged {
			sendmsg = []byte{m.data[3], m.data[2], m.data[1], m.data[0]}
		} else {
			sendmsg = m.data
		}
		_, err = s.sock.Write(sendmsg)
		return
	}
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

func (s *msgStream) CloseStream() error {
	return s.sock.Close()
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
